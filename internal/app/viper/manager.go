package viper

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/fileutil"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/paths/xdg"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
)

// Manager implements out.ConfigStore using Viper for loading and go-toml/v2 for
// writing, with environment variable override support.
type Manager struct {
	v    *viper.Viper
	path string
	mu   sync.RWMutex
	cfg  *coreconfig.Config
}

// NewManager creates a new Manager. If path is empty, a default path under the
// user's config directory is used.
func NewManager(path string) *Manager {
	if path == "" {
		path = defaultConfigPath()
	}
	return &Manager{
		v:    viper.New(),
		path: path,
	}
}

// defaultConfigPath computes the default config file path via the xdg adapter.
func defaultConfigPath() string {
	return xdg.Default().ConfigFile()
}

// setDefaults populates viper with default configuration values using
// snake_case TOML keys.
func (m *Manager) setDefaults(v *viper.Viper) {
	def := coreconfig.Default()

	v.SetDefault("bitwarden.email", def.Bitwarden.Email)
	v.SetDefault("bitwarden.region", string(def.Bitwarden.Region))
	v.SetDefault("bitwarden.server_url", def.Bitwarden.ServerURL)
	v.SetDefault("device.identifier", def.Device.Identifier)

	v.SetDefault("sync.revision_check_interval", def.Sync.RevisionCheckInterval.String())

	v.SetDefault("security.background_sync.enabled", def.Security.BackgroundSync.Enabled)
	v.SetDefault("security.background_sync.interval", def.Security.BackgroundSync.Interval.String())
	v.SetDefault("security.background_sync.retry_timeout", def.Security.BackgroundSync.RetryTimeout.String())
	v.SetDefault("security.idle_relock_after", def.Security.IdleRelockAfter.String())
	v.SetDefault("security.resident_relock_after", def.Security.ResidentRelockAfter.String())

	v.SetDefault("actions.clipboard_clear_after", def.Actions.ClipboardClearAfter.String())
	v.SetDefault("actions.close_after_copy", def.Actions.CloseAfterCopy)
	v.SetDefault("actions.default_primary_action", string(def.Actions.DefaultPrimaryAction))

	v.SetDefault("appearance.ui_scale", def.Appearance.UIScale)
	v.SetDefault("appearance.color_scheme", string(def.Appearance.ColorScheme))

	v.SetDefault("cache.ttl", def.Cache.TTL.String())
}

// decodeConfig reads current viper settings into a Config struct.
func (m *Manager) decodeConfig(v *viper.Viper) *coreconfig.Config {
	cfg := coreconfig.Default()

	// Bitwarden
	cfg.Bitwarden.Email = v.GetString("bitwarden.email")
	if r := v.GetString("bitwarden.region"); r != "" {
		cfg.Bitwarden.Region = coreconfig.Region(r)
	}
	cfg.Bitwarden.ServerURL = v.GetString("bitwarden.server_url")
	cfg.Device.Identifier = strings.TrimSpace(v.GetString("device.identifier"))

	// Sync
	if d := v.GetDuration("sync.revision_check_interval"); d > 0 {
		cfg.Sync.RevisionCheckInterval = d
	}

	// Security
	cfg.Security.BackgroundSync.Enabled = v.GetBool("security.background_sync.enabled")
	if d := v.GetDuration("security.background_sync.interval"); d > 0 {
		cfg.Security.BackgroundSync.Interval = d
	}
	if d := v.GetDuration("security.background_sync.retry_timeout"); d > 0 {
		cfg.Security.BackgroundSync.RetryTimeout = d
	}
	if d := v.GetDuration("security.idle_relock_after"); d > 0 {
		cfg.Security.IdleRelockAfter = d
	}
	if d := v.GetDuration("security.resident_relock_after"); d > 0 {
		cfg.Security.ResidentRelockAfter = d
	}

	// Actions
	if d := v.GetDuration("actions.clipboard_clear_after"); d > 0 {
		cfg.Actions.ClipboardClearAfter = d
	}
	cfg.Actions.CloseAfterCopy = v.GetBool("actions.close_after_copy")
	if a := v.GetString("actions.default_primary_action"); a != "" {
		cfg.Actions.DefaultPrimaryAction = coreconfig.PrimaryAction(a)
	}

	// Appearance
	cfg.Appearance.UIScale = v.GetFloat64("appearance.ui_scale")
	if c := v.GetString("appearance.color_scheme"); c != "" {
		cfg.Appearance.ColorScheme = coreconfig.ColorScheme(c)
	}

	// Cache
	if d := v.GetDuration("cache.ttl"); d > 0 {
		cfg.Cache.TTL = d
	}

	return cfg
}

// configToMap converts a Config into a nested map with snake_case keys,
// suitable for TOML marshaling.
func configToMap(cfg *coreconfig.Config) map[string]any {
	return map[string]any{
		"bitwarden": map[string]any{
			"email":      cfg.Bitwarden.Email,
			"region":     string(cfg.Bitwarden.Region),
			"server_url": cfg.Bitwarden.ServerURL,
		},
		"device": map[string]any{
			"identifier": cfg.Device.Identifier,
		},
		"sync": map[string]any{
			"revision_check_interval": cfg.Sync.RevisionCheckInterval.String(),
		},
		"security": map[string]any{
			"background_sync": map[string]any{
				"enabled":       cfg.Security.BackgroundSync.Enabled,
				"interval":      cfg.Security.BackgroundSync.Interval.String(),
				"retry_timeout": cfg.Security.BackgroundSync.RetryTimeout.String(),
			},
			"idle_relock_after":     cfg.Security.IdleRelockAfter.String(),
			"resident_relock_after": cfg.Security.ResidentRelockAfter.String(),
		},
		"actions": map[string]any{
			"clipboard_clear_after":  cfg.Actions.ClipboardClearAfter.String(),
			"close_after_copy":       cfg.Actions.CloseAfterCopy,
			"default_primary_action": string(cfg.Actions.DefaultPrimaryAction),
		},
		"appearance": map[string]any{
			"ui_scale":     cfg.Appearance.UIScale,
			"color_scheme": string(cfg.Appearance.ColorScheme),
		},
		"cache": map[string]any{
			"ttl": cfg.Cache.TTL.String(),
		},
	}
}

// Load reads the config file (if present), applies environment overrides, and
// returns a validated Config. A missing file is not an error — defaults are
// used instead. Missing email is tolerated during Load to allow first-run
// setup; all other validation errors are returned.
func (m *Manager) Load(ctx context.Context) (*coreconfig.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := m.v
	v.SetConfigFile(m.path)
	v.SetConfigType("toml")

	// Environment overrides: prefix GLSBW, dots become underscores
	v.SetEnvPrefix("GLSBW")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set defaults
	m.setDefaults(v)

	// Read config file — missing is OK
	if err := v.ReadInConfig(); err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, use defaults
		} else {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	cfg := m.decodeConfig(v)

	// Validate; tolerate only ErrEmailRequired for first-run scenarios
	err := coreconfig.Validate(cfg)
	if err != nil {
		if errors.Is(err, coreconfig.ErrEmailRequired) {
			errs := coreconfig.ValidateAll(cfg)
			onlyEmail := true
			for _, e := range errs {
				if !errors.Is(e, coreconfig.ErrEmailRequired) {
					onlyEmail = false
					break
				}
			}
			if !onlyEmail {
				return nil, fmt.Errorf("config validation: %w", err)
			}
		} else {
			return nil, fmt.Errorf("config validation: %w", err)
		}
	}

	if strings.TrimSpace(cfg.Device.Identifier) == "" {
		identifier, genErr := generateDeviceIdentifier()
		if genErr != nil {
			return nil, fmt.Errorf("generate device identifier: %w", genErr)
		}
		cfg.Device.Identifier = identifier
		if saveErr := m.saveLocked(ctx, cfg); saveErr != nil {
			return nil, saveErr
		}
		return cfg, nil
	}

	m.cfg = cfg
	return cfg, nil
}

// Save marshals cfg to TOML and writes it atomically to the config file.
func (m *Manager) Save(ctx context.Context, cfg *coreconfig.Config) error {
	if cfg == nil {
		return coreconfig.ErrNilConfig
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked(ctx, cfg)
}

func (m *Manager) saveLocked(ctx context.Context, cfg *coreconfig.Config) error {
	// Build a nested map with snake_case keys and marshal to TOML
	data, err := toml.Marshal(configToMap(cfg))
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := fileutil.AtomicWriteFile(ctx, m.path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	m.cfg = cfg
	return nil
}

func generateDeviceIdentifier() (string, error) {
	var raw [16]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate device identifier: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

// Watch installs a Viper file watcher. The onChange callback is invoked
// whenever the config file changes, but only if ctx is not yet done. When ctx
// is cancelled the callback is no longer invoked.
//
// Note: viper's WatchConfig runs its own goroutine internally; we do not need
// to spawn a goroutine to wait on ctx.Done().
func (m *Manager) Watch(ctx context.Context, onChange func(*coreconfig.Config)) error {
	m.mu.RLock()
	v := m.v
	m.mu.RUnlock()

	v.WatchConfig()
	v.OnConfigChange(func(in fsnotify.Event) {
		if ctx.Err() != nil {
			return
		}
		cfg := m.decodeConfig(v)
		m.mu.Lock()
		m.cfg = cfg
		m.mu.Unlock()
		onChange(cfg)
	})

	return nil
}

// Path returns the config file path.
func (m *Manager) Path() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.path
}

// Ensure interface compliance.
var _ interface {
	Load(ctx context.Context) (*coreconfig.Config, error)
	Save(ctx context.Context, cfg *coreconfig.Config) error
	Watch(ctx context.Context, onChange func(*coreconfig.Config)) error
} = (*Manager)(nil)
