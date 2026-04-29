package auth

import "time"

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
