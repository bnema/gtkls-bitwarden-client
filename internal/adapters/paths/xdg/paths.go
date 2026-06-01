// Package xdg provides deterministic, XDG-compliant paths for application
// configuration, cache, outbox, and state/log files.
package xdg

import (
	"os"
	"path/filepath"
)

const defaultAppName = "gtkls-bitwarden-client"

// Paths holds the application name used to derive all paths.
type Paths struct {
	AppName string
}

// New returns a Paths for the given app name. An empty name defaults to
// "gtkls-bitwarden-client".
func New(appName string) Paths {
	if appName == "" {
		appName = defaultAppName
	}
	return Paths{AppName: appName}
}

// Default returns a Paths for the default application name.
func Default() Paths {
	return Paths{AppName: defaultAppName}
}

// ConfigDir returns the configuration directory.
//   - $XDG_CONFIG_HOME/<app> if XDG_CONFIG_HOME is set.
//   - os.UserConfigDir()/<app> if that succeeds.
//   - ./<app> as last resort.
func (p Paths) ConfigDir() string {
	return filepath.Join(p.configBase(), p.AppName)
}

// ConfigFile returns ConfigDir()/config.toml.
func (p Paths) ConfigFile() string {
	return filepath.Join(p.ConfigDir(), "config.toml")
}

// CacheDir returns the cache directory.
//   - $XDG_CACHE_HOME/<app> if XDG_CACHE_HOME is set.
//   - os.UserCacheDir()/<app> if that succeeds.
//   - os.TempDir()/<app> as last resort.
func (p Paths) CacheDir() string {
	return filepath.Join(p.cacheBase(), p.AppName)
}

// CacheFile returns CacheDir()/cache.json.
func (p Paths) CacheFile() string {
	return filepath.Join(p.CacheDir(), "cache.json")
}

// OutboxFile returns CacheDir()/outbox.json.
func (p Paths) OutboxFile() string {
	return filepath.Join(p.CacheDir(), "outbox.json")
}

// StateDir returns the state directory.
//   - $XDG_STATE_HOME/<app> if XDG_STATE_HOME is set.
//   - $HOME/.local/state/<app> if HOME is set.
//   - os.TempDir()/<app>/state as last resort.
func (p Paths) StateDir() string {
	return filepath.Join(p.stateBase(), p.AppName)
}

// LogFile returns StateDir()/app.log.
func (p Paths) LogFile() string {
	return filepath.Join(p.StateDir(), "app.log")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (p Paths) configBase() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return dir
	}
	return "."
}

func (p Paths) cacheBase() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return dir
	}
	if dir, err := os.UserCacheDir(); err == nil {
		return dir
	}
	return os.TempDir()
}

func (p Paths) stateBase() string {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return dir
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".local", "state")
	}
	return filepath.Join(os.TempDir(), "state")
}
