package session

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

func TestUnlockEnvelopeValidatesEmailServerBootAndIgnoresLegacyExpiry(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	ref := AccountRef{Email: "a@b.com", ServerURL: "https://vault.example.com"}
	bootID := "boot-abc-123"

	envelope := UnlockEnvelope{
		Account:   ref,
		AccountID: "acc-42",
		BootID:    bootID,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	t.Run("valid", func(t *testing.T) {
		if err := envelope.Validate(ref, bootID, now); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("boot changed", func(t *testing.T) {
		if err := envelope.Validate(ref, "boot-other", now); err != ErrBootChanged {
			t.Fatalf("expected ErrBootChanged, got %v", err)
		}
	})

	t.Run("legacy expired envelope remains valid in same boot", func(t *testing.T) {
		late := now.Add(2 * time.Hour)
		if err := envelope.Validate(ref, bootID, late); err != nil {
			t.Fatalf("expected nil for legacy expired envelope in same boot, got %v", err)
		}
	})

	t.Run("account mismatch", func(t *testing.T) {
		otherRef := AccountRef{Email: "b@c.com", ServerURL: "https://other.example.com"}
		if err := envelope.Validate(otherRef, bootID, now); err != ErrAccountMismatch {
			t.Fatalf("expected ErrAccountMismatch, got %v", err)
		}
	})
}

func TestUnlockEnvelopeBackoffValidation(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	ref := AccountRef{Email: "a@b.com", ServerURL: "https://vault.example.com"}
	bootID := "boot-abc"

	// BackoffUntil in the future → should return ErrPINBackoff
	envelope := UnlockEnvelope{
		Account:      ref,
		BootID:       bootID,
		BackoffUntil: now.Add(30 * time.Second),
	}
	if err := envelope.Validate(ref, bootID, now); err != ErrPINBackoff {
		t.Fatalf("expected ErrPINBackoff, got %v", err)
	}

	// BackoffUntil in the past → should not return backoff error
	envelope.BackoffUntil = now.Add(-1 * time.Second)
	if err := envelope.Validate(ref, bootID, now); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	// BackoffUntil zero → should not return backoff error
	envelope.BackoffUntil = time.Time{}
	if err := envelope.Validate(ref, bootID, now); err != nil {
		t.Fatalf("expected nil when BackoffUntil is zero, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RecordPINFailure / ShouldDeleteAfterFailures tests
// ---------------------------------------------------------------------------

func TestRecordPINFailureBackoffAndClearsAtMax(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	t.Run("defaults PINMaxFailures to 5 when zero", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 0}
		e.RecordPINFailure(now)
		if e.PINMaxFailures != 5 {
			t.Fatalf("expected PINMaxFailures=5, got %d", e.PINMaxFailures)
		}
	})

	t.Run("first failure has 1s backoff", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 5}
		e.RecordPINFailure(now)
		if e.FailedAttempts != 1 {
			t.Fatalf("expected FailedAttempts=1, got %d", e.FailedAttempts)
		}
		want := now.Add(1 * time.Second)
		if !e.BackoffUntil.Equal(want) {
			t.Fatalf("expected BackoffUntil %v, got %v", want, e.BackoffUntil)
		}
	})

	t.Run("second failure has 2s backoff", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 5, FailedAttempts: 1}
		e.RecordPINFailure(now)
		if e.FailedAttempts != 2 {
			t.Fatalf("expected FailedAttempts=2, got %d", e.FailedAttempts)
		}
		want := now.Add(2 * time.Second)
		if !e.BackoffUntil.Equal(want) {
			t.Fatalf("expected BackoffUntil %v, got %v", want, e.BackoffUntil)
		}
	})

	t.Run("third failure has 4s backoff", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 5, FailedAttempts: 2}
		e.RecordPINFailure(now)
		if e.FailedAttempts != 3 {
			t.Fatalf("expected FailedAttempts=3, got %d", e.FailedAttempts)
		}
		want := now.Add(4 * time.Second)
		if !e.BackoffUntil.Equal(want) {
			t.Fatalf("expected BackoffUntil %v, got %v", want, e.BackoffUntil)
		}
	})

	t.Run("backoff caps at 1 minute", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 100, FailedAttempts: 59}
		e.RecordPINFailure(now)
		if e.FailedAttempts != 60 {
			t.Fatalf("expected FailedAttempts=60, got %d", e.FailedAttempts)
		}
		want := now.Add(60 * time.Second)
		if !e.BackoffUntil.Equal(want) {
			t.Fatalf("expected BackoffUntil %v, got %v", want, e.BackoffUntil)
		}
	})

	t.Run("ShouldDeleteAfterFailures false before max", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 5, FailedAttempts: 4}
		if e.ShouldDeleteAfterFailures() {
			t.Fatal("expected false before reaching max")
		}
	})

	t.Run("ShouldDeleteAfterFailures true at max", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 5, FailedAttempts: 5}
		if !e.ShouldDeleteAfterFailures() {
			t.Fatal("expected true at max")
		}
	})

	t.Run("ShouldDeleteAfterFailures true beyond max", func(t *testing.T) {
		e := &UnlockEnvelope{PINMaxFailures: 5, FailedAttempts: 7}
		if !e.ShouldDeleteAfterFailures() {
			t.Fatal("expected true beyond max")
		}
	})

	t.Run("defaults max to 5 for ShouldDeleteAfterFailures", func(t *testing.T) {
		e := &UnlockEnvelope{FailedAttempts: 5}
		if !e.ShouldDeleteAfterFailures() {
			t.Fatal("expected ShouldDeleteAfterFailures true with FailedAttempts=5 and zero max")
		}
	})
}

// ---------------------------------------------------------------------------
// Clone / Close tests
// ---------------------------------------------------------------------------

func TestTokenBundleAndUnlockMaterialCloneAndCloseNoAlias(t *testing.T) {
	t.Run("TokenBundle clone is independent", func(t *testing.T) {
		orig := TokenBundle{
			AccountID:                "acc-1",
			AccessToken:              []byte("secret-access-token"),
			RefreshToken:             []byte("secret-refresh-token"),
			RememberedTwoFactorToken: []byte("remembered-2fa-token"),
		}

		clone := orig.Clone()

		// Modify the clone's slices — orig should be untouched.
		clone.AccessToken[0] = 'X'
		clone.RefreshToken[0] = 'Y'
		clone.RememberedTwoFactorToken[0] = 'Z'

		if orig.AccessToken[0] != 's' {
			t.Fatal("Clone did not deep-copy AccessToken")
		}
		if orig.RefreshToken[0] != 's' {
			t.Fatal("Clone did not deep-copy RefreshToken")
		}
		if orig.RememberedTwoFactorToken[0] != 'r' {
			t.Fatal("Clone did not deep-copy RememberedTwoFactorToken")
		}

		// Ensure non-slice fields are still shared by value (fine).
		if clone.AccountID != orig.AccountID {
			t.Fatal("Clone should share value fields")
		}
	})

	t.Run("TokenBundle close zeroes backing arrays", func(t *testing.T) {
		access := []byte("access-token")
		refresh := []byte("refresh-token")
		remembered := []byte("remembered-2fa-token")
		tb := &TokenBundle{
			AccessToken:              access,
			RefreshToken:             refresh,
			RememberedTwoFactorToken: remembered,
		}

		tb.Close()

		// Backing arrays should be zeroed.
		for i, b := range access {
			if b != 0 {
				t.Fatalf("AccessToken backing[%d] = %d, want 0", i, b)
			}
		}
		for i, b := range refresh {
			if b != 0 {
				t.Fatalf("RefreshToken backing[%d] = %d, want 0", i, b)
			}
		}
		for i, b := range remembered {
			if b != 0 {
				t.Fatalf("RememberedTwoFactorToken backing[%d] = %d, want 0", i, b)
			}
		}

		if tb.AccessToken != nil {
			t.Fatal("AccessToken should be nil after Close")
		}
		if tb.RefreshToken != nil {
			t.Fatal("RefreshToken should be nil after Close")
		}
		if tb.RememberedTwoFactorToken != nil {
			t.Fatal("RememberedTwoFactorToken should be nil after Close")
		}
	})

	t.Run("UnlockMaterial clone is independent", func(t *testing.T) {
		orig := UnlockMaterial{
			CacheKey: []byte("cache-key-bytes"),
			UserKey:  []byte("user-key-bytes"),
		}

		clone := orig.Clone()

		clone.CacheKey[0] = 'X'
		clone.UserKey[0] = 'Y'

		if orig.CacheKey[0] != 'c' {
			t.Fatal("Clone did not deep-copy CacheKey")
		}
		if orig.UserKey[0] != 'u' {
			t.Fatal("Clone did not deep-copy UserKey")
		}
	})

	t.Run("UnlockMaterial close zeroes backing arrays", func(t *testing.T) {
		ck := []byte("cache-key")
		uk := []byte("user-key")
		um := &UnlockMaterial{
			CacheKey: ck,
			UserKey:  uk,
		}

		um.Close()

		for i, b := range ck {
			if b != 0 {
				t.Fatalf("CacheKey backing[%d] = %d, want 0", i, b)
			}
		}
		for i, b := range uk {
			if b != 0 {
				t.Fatalf("UserKey backing[%d] = %d, want 0", i, b)
			}
		}

		if um.CacheKey != nil {
			t.Fatal("CacheKey should be nil after Close")
		}
		if um.UserKey != nil {
			t.Fatal("UserKey should be nil after Close")
		}
	})

	t.Run("clone of nil slices stays nil", func(t *testing.T) {
		tb := TokenBundle{}.Clone()
		if tb.AccessToken != nil {
			t.Fatal("expected nil AccessToken")
		}
		if tb.RefreshToken != nil {
			t.Fatal("expected nil RefreshToken")
		}
		if tb.RememberedTwoFactorToken != nil {
			t.Fatal("expected nil RememberedTwoFactorToken")
		}

		um := UnlockMaterial{}.Clone()
		if um.CacheKey != nil {
			t.Fatal("expected nil CacheKey")
		}
		if um.UserKey != nil {
			t.Fatal("expected nil UserKey")
		}
	})

	t.Run("close on empty bundle is safe", func(t *testing.T) {
		tb := &TokenBundle{}
		tb.Close() // should not panic

		um := &UnlockMaterial{}
		um.Close() // should not panic
	})
}

func TestUnlockEnvelopeCloneAndCloseNoAlias(t *testing.T) {
	t.Run("clone is independent", func(t *testing.T) {
		orig := UnlockEnvelope{
			Salt:       []byte("sixteen-byte-salt"),
			Ciphertext: []byte("encrypted-data-bytes"),
		}

		clone := orig.Clone()

		clone.Salt[0] = 'X'
		clone.Ciphertext[0] = 'Y'

		if orig.Salt[0] != 's' {
			t.Fatal("Clone did not deep-copy Salt")
		}
		if orig.Ciphertext[0] != 'e' {
			t.Fatal("Clone did not deep-copy Ciphertext")
		}
	})

	t.Run("close zeroes backing arrays", func(t *testing.T) {
		salt := []byte("salt-for-test")
		ciphertext := []byte("ciphertext-for-test")
		e := &UnlockEnvelope{
			Salt:       salt,
			Ciphertext: ciphertext,
		}

		e.Close()

		for i, b := range salt {
			if b != 0 {
				t.Fatalf("Salt backing[%d] = %d, want 0", i, b)
			}
		}
		for i, b := range ciphertext {
			if b != 0 {
				t.Fatalf("Ciphertext backing[%d] = %d, want 0", i, b)
			}
		}

		if e.Salt != nil {
			t.Fatal("Salt should be nil after Close")
		}
		if e.Ciphertext != nil {
			t.Fatal("Ciphertext should be nil after Close")
		}
	})

	t.Run("clone of nil slices stays nil", func(t *testing.T) {
		e := UnlockEnvelope{}.Clone()
		if e.Salt != nil {
			t.Fatal("expected nil Salt")
		}
		if e.Ciphertext != nil {
			t.Fatal("expected nil Ciphertext")
		}
	})

	t.Run("close on empty envelope is safe", func(t *testing.T) {
		e := &UnlockEnvelope{}
		e.Close() // should not panic
	})
}
