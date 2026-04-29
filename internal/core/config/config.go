package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Region string

const (
	RegionUS         Region = "us"
	RegionEU         Region = "eu"
	RegionSelfHosted Region = "self_hosted"
)

type PrimaryAction string

const (
	ActionCopyPassword PrimaryAction = "copy_password"
	ActionCopyUsername PrimaryAction = "copy_username"
	ActionOpenURL      PrimaryAction = "open_url"
	ActionOpenDetail   PrimaryAction = "open_detail"
)

type ColorScheme string

const (
	ColorSchemeDark  ColorScheme = "dark"
	ColorSchemeLight ColorScheme = "light"
)

type Config struct {
	Bitwarden  Bitwarden
	Sync       Sync
	Security   Security
	Actions    Actions
	Appearance Appearance
	Cache      Cache
}

type Bitwarden struct {
	Email     string
	Region    Region
	ServerURL string
}

type Sync struct {
	RevisionCheckInterval time.Duration
}

type BackgroundSync struct {
	Enabled      bool
	Interval     time.Duration
	RetryTimeout time.Duration
}

type Security struct {
	BackgroundSync      BackgroundSync
	IdleRelockAfter     time.Duration
	ResidentRelockAfter time.Duration
}

type Actions struct {
	ClipboardClearAfter  time.Duration
	CloseAfterCopy       bool
	DefaultPrimaryAction PrimaryAction
}

type Appearance struct {
	UIScale     float64
	ColorScheme ColorScheme
}

type Cache struct {
	TTL time.Duration
}

var (
	ErrEmailRequired        = errors.New("config: email is required")
	ErrInvalidRegion        = errors.New("config: region must be us, eu, or self_hosted")
	ErrInvalidServerURL     = errors.New("config: self_hosted server_url must be an absolute https URL")
	ErrInvalidUIScale       = errors.New("config: ui_scale must be between 0.5 and 3.0")
	ErrInvalidPrimaryAction = errors.New("config: primary action must be copy_password, copy_username, open_url, or open_detail")
)

func Default() *Config {
	return &Config{
		Bitwarden: Bitwarden{
			Region: RegionUS,
		},
		Sync: Sync{
			RevisionCheckInterval: 5 * time.Minute,
		},
		Security: Security{
			BackgroundSync: BackgroundSync{
				Enabled:      true,
				Interval:     15 * time.Minute,
				RetryTimeout: 30 * time.Second,
			},
			IdleRelockAfter:     15 * time.Minute,
			ResidentRelockAfter: 30 * time.Minute,
		},
		Actions: Actions{
			ClipboardClearAfter:  45 * time.Second,
			CloseAfterCopy:       true,
			DefaultPrimaryAction: ActionCopyPassword,
		},
		Appearance: Appearance{
			UIScale:     1.0,
			ColorScheme: ColorSchemeDark,
		},
		Cache: Cache{
			TTL: 5 * time.Minute,
		},
	}
}

func Validate(cfg *Config) error {
	if cfg.Bitwarden.Email == "" {
		return ErrEmailRequired
	}

	switch cfg.Bitwarden.Region {
	case RegionUS, RegionEU, RegionSelfHosted:
		// valid
	default:
		return ErrInvalidRegion
	}

	if cfg.Bitwarden.Region == RegionSelfHosted {
		if cfg.Bitwarden.ServerURL == "" {
			return ErrInvalidServerURL
		}
		u, err := url.Parse(cfg.Bitwarden.ServerURL)
		if err != nil || u.Scheme != "https" || !strings.HasPrefix(cfg.Bitwarden.ServerURL, "https://") {
			return ErrInvalidServerURL
		}
	}

	if cfg.Appearance.UIScale < 0.5 || cfg.Appearance.UIScale > 3.0 {
		return ErrInvalidUIScale
	}

	switch cfg.Actions.DefaultPrimaryAction {
	case ActionCopyPassword, ActionCopyUsername, ActionOpenURL, ActionOpenDetail:
		// valid
	default:
		return ErrInvalidPrimaryAction
	}

	return nil
}

// ValidateAll returns a slice of all validation errors found.
func ValidateAll(cfg *Config) []error {
	var errs []error
	if err := Validate(cfg); err != nil {
		errs = append(errs, err)
	}

	if cfg.Bitwarden.Email == "" {
		errs = append(errs, ErrEmailRequired)
	}

	switch cfg.Bitwarden.Region {
	case RegionUS, RegionEU, RegionSelfHosted:
	default:
		errs = append(errs, ErrInvalidRegion)
	}

	if cfg.Bitwarden.Region == RegionSelfHosted {
		if cfg.Bitwarden.ServerURL == "" {
			errs = append(errs, ErrInvalidServerURL)
		} else {
			u, err := url.Parse(cfg.Bitwarden.ServerURL)
			if err != nil || u.Scheme != "https" || !strings.HasPrefix(cfg.Bitwarden.ServerURL, "https://") {
				errs = append(errs, ErrInvalidServerURL)
			}
		}
	}

	if cfg.Appearance.UIScale < 0.5 || cfg.Appearance.UIScale > 3.0 {
		errs = append(errs, ErrInvalidUIScale)
	}

	switch cfg.Actions.DefaultPrimaryAction {
	case ActionCopyPassword, ActionCopyUsername, ActionOpenURL, ActionOpenDetail:
	default:
		errs = append(errs, ErrInvalidPrimaryAction)
	}

	return errs
}

// String returns a human-readable string representation of the region.
func (r Region) String() string {
	switch r {
	case RegionUS:
		return "us"
	case RegionEU:
		return "eu"
	case RegionSelfHosted:
		return "self_hosted"
	default:
		return fmt.Sprintf("unknown(%s)", string(r))
	}
}
