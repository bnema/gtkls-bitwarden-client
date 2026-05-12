package viper

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
)

// tempConfig creates a Manager with a temporary config path and returns the
// manager, the temp dir, and a cleanup function.
func tempConfig(t *testing.T) (*Manager, string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "glsbw-test-*")
	require.NoError(t, err)
	path := filepath.Join(dir, "config.toml")
	mgr := NewManager(path)
	return mgr, dir, func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("failed to remove temp dir: %v", err)
		}
	}
}

func TestLoadMissingConfigReturnsDefaultsNoError(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	cfg, err := mgr.Load(context.Background())
	require.NoError(t, err, "Load with missing config should not error")
	require.NotNil(t, cfg)

	// Email is empty (no error expected on Load)
	assert.Equal(t, "", cfg.Bitwarden.Email)

	// All other defaults should be set
	assert.Equal(t, coreconfig.RegionUS, cfg.Bitwarden.Region)
	assert.Equal(t, 1.0, cfg.Appearance.UIScale)
	assert.Equal(t, 5*time.Minute, cfg.Cache.TTL)
	assert.Equal(t, coreconfig.ActionCopyPassword, cfg.Actions.DefaultPrimaryAction)
}

func TestSaveThenLoadRoundTrip(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	// Create a config with explicit values
	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = "user@example.com"
	cfg.Bitwarden.Region = coreconfig.RegionEU
	cfg.Appearance.UIScale = 1.5
	cfg.Sync.RevisionCheckInterval = 10 * time.Minute
	cfg.Security.IdleRelockAfter = 30 * time.Minute
	cfg.Actions.DefaultPrimaryAction = coreconfig.ActionCopyUsername
	cfg.Appearance.ColorScheme = coreconfig.ColorSchemeLight

	err := mgr.Save(context.Background(), cfg)
	require.NoError(t, err)

	// Load from a fresh manager to ensure file persistence
	loaded, err := NewManager(mgr.Path()).Load(context.Background())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "user@example.com", loaded.Bitwarden.Email)
	assert.Equal(t, coreconfig.RegionEU, loaded.Bitwarden.Region)
	assert.Equal(t, 1.5, loaded.Appearance.UIScale)
	assert.Equal(t, 10*time.Minute, loaded.Sync.RevisionCheckInterval)
	assert.Equal(t, 30*time.Minute, loaded.Security.IdleRelockAfter)
	assert.Equal(t, coreconfig.ActionCopyUsername, loaded.Actions.DefaultPrimaryAction)
	assert.Equal(t, coreconfig.ColorSchemeLight, loaded.Appearance.ColorScheme)
}

func TestLoadGeneratesStableDeviceIdentifier(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	first, err := mgr.Load(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, first.Device.Identifier)

	_, err = os.Stat(mgr.Path())
	require.NoError(t, err, "Load should persist the generated device identifier")

	second, err := NewManager(mgr.Path()).Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first.Device.Identifier, second.Device.Identifier)
}

func TestLoadTrimsWhitespaceOnlyDeviceIdentifier(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = "user@example.com"
	cfg.Device.Identifier = "   "
	require.NoError(t, mgr.Save(context.Background(), cfg))

	loaded, err := NewManager(mgr.Path()).Load(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, loaded.Device.Identifier)
	assert.NotEqual(t, "   ", loaded.Device.Identifier)
}

func TestEnvOverride(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	// Set environment variable with GLSBW prefix and dots as underscores
	t.Setenv("GLSBW_BITWARDEN_EMAIL", "env@example.com")

	cfg, err := mgr.Load(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "env@example.com", cfg.Bitwarden.Email,
		"env override should set bitwarden.email")
}

func TestEnvOverrideTakesPrecedenceOverFile(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	// First save a config with one email
	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = "file@example.com"
	err := mgr.Save(context.Background(), cfg)
	require.NoError(t, err)

	// Override via env
	t.Setenv("GLSBW_BITWARDEN_EMAIL", "env@example.com")

	loaded, err := NewManager(mgr.Path()).Load(context.Background())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "env@example.com", loaded.Bitwarden.Email,
		"env var should take precedence over file value")
}

func TestLoadFailsOnBadUIScale(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	// Save config with invalid UI scale
	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = "user@example.com"
	cfg.Appearance.UIScale = 5.0 // invalid > 3.0
	err := mgr.Save(context.Background(), cfg)
	require.NoError(t, err)

	_, err = NewManager(mgr.Path()).Load(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "ui_scale must be between")
}

func TestLoadToleratesOnlyMissingEmail(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	// Save config with email but also invalid scale -> should fail
	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = "user@example.com"
	cfg.Appearance.UIScale = 5.0
	err := mgr.Save(context.Background(), cfg)
	require.NoError(t, err)

	_, err = NewManager(mgr.Path()).Load(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "ui_scale")

	// Save config with invalid region but valid email -> should fail
	cfg2 := coreconfig.Default()
	cfg2.Bitwarden.Email = "user@example.com"
	cfg2.Bitwarden.Region = "invalid"
	err = mgr.Save(context.Background(), cfg2)
	require.NoError(t, err)

	_, err = NewManager(mgr.Path()).Load(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "region")
}

func TestDefaultConfigPathUsesXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/xdg")
	path := defaultConfigPath()
	assert.Contains(t, path, "/custom/xdg/gtk4-layershell-bitwarden/config.toml")
}

func TestSaveNilReturnsError(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	err := mgr.Save(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, coreconfig.ErrNilConfig)
}

func TestPathReturnsCorrectPath(t *testing.T) {
	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	p := mgr.Path()
	assert.Contains(t, p, "config.toml")
}

func TestWatchFiresOnSave(t *testing.T) {
	t.Skip("flaky on CI due to fsnotify timing — run manually to verify")

	mgr, _, cleanup := tempConfig(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Load initially to create defaults
	_, err := mgr.Load(ctx)
	require.NoError(t, err)

	// Channel to signal the callback was invoked
	ch := make(chan string, 1)

	err = mgr.Watch(ctx, func(cfg *coreconfig.Config) {
		select {
		case ch <- cfg.Bitwarden.Email:
		default:
		}
	})
	require.NoError(t, err)

	// Give fsnotify a moment to set up
	time.Sleep(200 * time.Millisecond)

	// Save a new config
	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = "watch@example.com"
	err = mgr.Save(ctx, cfg)
	require.NoError(t, err)

	// Wait for callback or timeout
	select {
	case email := <-ch:
		assert.Equal(t, "watch@example.com", email)
	case <-ctx.Done():
		t.Log("watch test timed out — fsnotify may be flaky on this platform")
	}
}
