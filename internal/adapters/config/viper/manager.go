package viper

import (
	"context"
	"errors"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"

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

// defaultConfigPath computes the default config file path.
func defaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			base = "." // last resort
		} else {
			base = dir
		}
	}
	return filepath.Join(base, "gtk4-layershell-bitwarden", "config.toml")
}

// setDefaults populates viper with default configuration values using
// snake_case TOML keys.
func (m *Manager) setDefaults(v *viper.Viper) {
	def := coreconfig.Default()

	v.SetDefault("bitwarden.email", def.Bitwarden.Email)
	v.SetDefault("bitwarden.region", string(def.Bitwarden.Region))
	v.SetDefault("bitwarden.server_url", def.Bitwarden.ServerURL)

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
			if onlyEmail {
				m.cfg = cfg
				return cfg, nil
			}
		}
		return nil, fmt.Errorf("config validation: %w", err)
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

	// Ensure parent directory exists with 0700
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}

	// Build a nested map with snake_case keys and marshal to TOML
	data, err := toml.Marshal(configToMap(cfg))
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Atomic write: temp file + rename
	tmpPath := m.path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, m.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename config file: %w", err)
	}

	m.cfg = cfg
	return nil
}

// Watch starts watching the config file for changes. It returns immediately
// after installing the watcher. The onChange callback is invoked whenever the
// file changes, but only if ctx is not yet done. When ctx is cancelled the
// callback will no longer be called.
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

	go func() {
		<-ctx.Done()
	}()

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
