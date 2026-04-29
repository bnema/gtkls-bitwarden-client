package config

import (
	"testing"
	"time"
)

func TestDefaultsAcceptedAfterSettingEmail(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"

	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error with email set, got %v", err)
	}
}

func TestDefaultsValidateMissingEmail(t *testing.T) {
	cfg := Default()
	// Email is empty by default
	if err := Validate(cfg); err != ErrEmailRequired {
		t.Errorf("expected ErrEmailRequired, got %v", err)
	}
}

func TestRejectUnsafeScale(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"

	// Too low
	cfg.Appearance.UIScale = 0.4
	if err := Validate(cfg); err != ErrInvalidUIScale {
		t.Errorf("expected ErrInvalidUIScale for 0.4, got %v", err)
	}

	// Too high
	cfg.Appearance.UIScale = 3.1
	if err := Validate(cfg); err != ErrInvalidUIScale {
		t.Errorf("expected ErrInvalidUIScale for 3.1, got %v", err)
	}
}

func TestAcceptBoundaryScale(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"

	cfg.Appearance.UIScale = 0.5
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for 0.5, got %v", err)
	}

	cfg.Appearance.UIScale = 3.0
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for 3.0, got %v", err)
	}
}

func TestRejectInvalidRegion(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"
	cfg.Bitwarden.Region = "invalid"

	if err := Validate(cfg); err != ErrInvalidRegion {
		t.Errorf("expected ErrInvalidRegion, got %v", err)
	}
}

func TestRejectBadSelfHostedURL(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"
	cfg.Bitwarden.Region = RegionSelfHosted

	// Empty URL
	cfg.Bitwarden.ServerURL = ""
	if err := Validate(cfg); err != ErrInvalidServerURL {
		t.Errorf("expected ErrInvalidServerURL for empty URL, got %v", err)
	}

	// HTTP URL
	cfg.Bitwarden.ServerURL = "http://example.com"
	if err := Validate(cfg); err != ErrInvalidServerURL {
		t.Errorf("expected ErrInvalidServerURL for http URL, got %v", err)
	}

	// Relative URL
	cfg.Bitwarden.ServerURL = "/relative/path"
	if err := Validate(cfg); err != ErrInvalidServerURL {
		t.Errorf("expected ErrInvalidServerURL for relative URL, got %v", err)
	}
}

func TestAcceptSelfHostedURL(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"
	cfg.Bitwarden.Region = RegionSelfHosted
	cfg.Bitwarden.ServerURL = "https://vault.example.com"

	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for valid self-hosted URL, got %v", err)
	}
}

func TestAcceptPrimaryActionCopyPassword(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"
	cfg.Actions.DefaultPrimaryAction = ActionCopyPassword

	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for copy_password, got %v", err)
	}
}

func TestRejectInvalidPrimaryAction(t *testing.T) {
	cfg := Default()
	cfg.Bitwarden.Email = "test@example.com"
	cfg.Actions.DefaultPrimaryAction = "invalid_action"

	if err := Validate(cfg); err != ErrInvalidPrimaryAction {
		t.Errorf("expected ErrInvalidPrimaryAction, got %v", err)
	}
}

func TestDefaultValues(t *testing.T) {
	cfg := Default()

	if cfg.Bitwarden.Region != RegionUS {
		t.Errorf("expected region us, got %s", cfg.Bitwarden.Region)
	}
	if cfg.Sync.RevisionCheckInterval != 5*time.Minute {
		t.Errorf("expected revision TTL 5m, got %v", cfg.Sync.RevisionCheckInterval)
	}
	if !cfg.Security.BackgroundSync.Enabled {
		t.Error("expected background sync enabled")
	}
	if cfg.Security.BackgroundSync.Interval != 15*time.Minute {
		t.Errorf("expected background interval 15m, got %v", cfg.Security.BackgroundSync.Interval)
	}
	if cfg.Security.BackgroundSync.RetryTimeout != 30*time.Second {
		t.Errorf("expected retry 30s, got %v", cfg.Security.BackgroundSync.RetryTimeout)
	}
	if cfg.Security.IdleRelockAfter != 15*time.Minute {
		t.Errorf("expected idle relock 15m, got %v", cfg.Security.IdleRelockAfter)
	}
	if cfg.Security.ResidentRelockAfter != 30*time.Minute {
		t.Errorf("expected resident 30m, got %v", cfg.Security.ResidentRelockAfter)
	}
	if cfg.Actions.ClipboardClearAfter != 45*time.Second {
		t.Errorf("expected clipboard 45s, got %v", cfg.Actions.ClipboardClearAfter)
	}
	if !cfg.Actions.CloseAfterCopy {
		t.Error("expected close after copy true")
	}
	if cfg.Actions.DefaultPrimaryAction != ActionCopyPassword {
		t.Errorf("expected primary action copy_password, got %s", cfg.Actions.DefaultPrimaryAction)
	}
	if cfg.Appearance.UIScale != 1.0 {
		t.Errorf("expected ui scale 1.0, got %f", cfg.Appearance.UIScale)
	}
	if cfg.Appearance.ColorScheme != ColorSchemeDark {
		t.Errorf("expected color scheme dark, got %s", cfg.Appearance.ColorScheme)
	}
}
