package auth

import (
	"context"
	"time"
)

type LockState string

const (
	LockStateLocked    LockState = "locked"
	LockStateUnlocking LockState = "unlocking"
	LockStateUnlocked  LockState = "unlocked"
)

type UnlockSession struct {
	AccountID  string
	Email      string
	UnlockedAt time.Time
}

type RelockPolicy struct {
	IdleTimeout     time.Duration
	ResidentTimeout time.Duration
}

type TwoFactorProvider string

const (
	TwoFactorProviderAuthenticator TwoFactorProvider = "authenticator"
	TwoFactorProviderEmail         TwoFactorProvider = "email"
	TwoFactorProviderYubiKey       TwoFactorProvider = "yubikey"
	TwoFactorProviderDuo           TwoFactorProvider = "duo"
)

type TwoFactorChallenge struct {
	Providers []TwoFactorProvider
	Handle    any
	closeFn   func()
}

func NewTwoFactorChallenge(providers []TwoFactorProvider, handle any, closeFn func()) *TwoFactorChallenge {
	copied := make([]TwoFactorProvider, len(providers))
	copy(copied, providers)
	return &TwoFactorChallenge{Providers: copied, Handle: handle, closeFn: closeFn}
}

func (c *TwoFactorChallenge) Close() {
	if c != nil && c.closeFn != nil {
		c.closeFn()
	}
}

type TwoFactorPrompt func(ctx context.Context, providers []TwoFactorProvider) (provider TwoFactorProvider, code string, remember bool, err error)
