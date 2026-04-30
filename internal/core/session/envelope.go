package session

import (
	"errors"
	"time"
)

var (
	ErrUnlockExpired   = errors.New("unlock envelope has expired")
	ErrBootChanged     = errors.New("boot ID has changed")
	ErrAccountMismatch = errors.New("account mismatch")
	ErrPINBackoff      = errors.New("PIN backoff in effect")
)

// Validate checks the envelope against the supplied account reference, boot ID,
// and current time. It returns an appropriate sentinel error when a check fails,
// or nil when all checks pass.
func (e UnlockEnvelope) Validate(ref AccountRef, bootID string, now time.Time) error {
	if e.Account != ref {
		return ErrAccountMismatch
	}
	if e.BootID != bootID {
		return ErrBootChanged
	}
	if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
		return ErrUnlockExpired
	}
	if !e.BackoffUntil.IsZero() && now.Before(e.BackoffUntil) {
		return ErrPINBackoff
	}
	return nil
}

// RecordPINFailure increments the failed-attempt counter, sets a sane default
// for PINMaxFailures if not already configured, and applies exponential backoff
// (1s, 2s, 4s, …) capped at 1 minute. Overflow is avoided for very high
// attempt counts by special-casing large values.
func (e *UnlockEnvelope) RecordPINFailure(now time.Time) {
	e.FailedAttempts++

	if e.PINMaxFailures <= 0 {
		e.PINMaxFailures = 5
	}

	n := e.FailedAttempts
	// Compute 2^(n-1) seconds, capped at 60.
	var seconds uint64
	const maxBackoffSecs uint64 = 60
	switch {
	case n <= 0:
		seconds = 0
	case n > 63: // 2^(n-1) would overflow a uint64, cap immediately
		seconds = maxBackoffSecs
	default:
		// 1 << (n-1), safe because n <= 63 here.
		s := uint64(1) << uint(n-1)
		if s > maxBackoffSecs {
			seconds = maxBackoffSecs
		} else {
			seconds = s
		}
	}

	e.BackoffUntil = now.Add(time.Duration(seconds) * time.Second)
}

// ShouldDeleteAfterFailures returns true when FailedAttempts reaches or exceeds
// the maximum allowed PIN failures. If PINMaxFailures is not configured (<= 0)
// it defaults to 5.
func (e UnlockEnvelope) ShouldDeleteAfterFailures() bool {
	max := e.PINMaxFailures
	if max <= 0 {
		max = 5
	}
	return e.FailedAttempts >= max
}
