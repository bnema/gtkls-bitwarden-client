package auth

import (
	"testing"
	"time"
)

func TestLockStateConstants(t *testing.T) {
	if LockStateLocked != "locked" {
		t.Errorf("LockStateLocked = %q, want %q", LockStateLocked, "locked")
	}
	if LockStateUnlocking != "unlocking" {
		t.Errorf("LockStateUnlocking = %q, want %q", LockStateUnlocking, "unlocking")
	}
	if LockStateUnlocked != "unlocked" {
		t.Errorf("LockStateUnlocked = %q, want %q", LockStateUnlocked, "unlocked")
	}
}

func TestRelockPolicyDurations(t *testing.T) {
	p := RelockPolicy{
		IdleTimeout:     15 * time.Minute,
		ResidentTimeout: 30 * time.Minute,
	}
	if p.IdleTimeout != 15*time.Minute {
		t.Errorf("IdleTimeout = %v, want %v", p.IdleTimeout, 15*time.Minute)
	}
	if p.ResidentTimeout != 30*time.Minute {
		t.Errorf("ResidentTimeout = %v, want %v", p.ResidentTimeout, 30*time.Minute)
	}
}

func TestUnlockSessionZeroValue(t *testing.T) {
	var s UnlockSession
	if s.AccountID != "" {
		t.Error("expected zero-value AccountID to be empty")
	}
	if s.Email != "" {
		t.Error("expected zero-value Email to be empty")
	}
	if !s.UnlockedAt.IsZero() {
		t.Error("expected zero-value UnlockedAt to be zero")
	}
}
