package pinenvelope

import (
	"context"
	"testing"
	"time"

	session "github.com/bnema/gtkls-bitwarden-client/internal/core/session"
)

func testConfig() ServiceConfig {
	return ServiceConfig{
		TTL:         1 * time.Hour,
		MaxFailures: 5,
		KDFTime:     1,
		KDFMemory:   64,
		KDFThreads:  1,
	}
}

var (
	testRef    = session.AccountRef{Email: "test@example.com", ServerURL: "https://vault.example.com"}
	testPIN    = "correct-pin"
	testBootID = "boot-abc-123"
)

func testMaterial() session.UnlockMaterial {
	return session.UnlockMaterial{
		CacheKey: []byte("cache-key-data"),
		UserKey:  []byte("user-key-data"),
	}
}

func TestCreateOpenEnvelopeWithCorrectPIN(t *testing.T) {
	svc := New(testConfig())
	material := testMaterial()
	ctx := context.Background()

	env, err := svc.Create(ctx, testRef, material, testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Basic envelope field checks.
	if env.Version != session.UnlockEnvelopeVersion {
		t.Fatalf("expected version %d, got %d", session.UnlockEnvelopeVersion, env.Version)
	}
	if env.Account != testRef {
		t.Fatalf("expected account %+v, got %+v", testRef, env.Account)
	}
	if env.BootID != testBootID {
		t.Fatalf("expected bootID %q, got %q", testBootID, env.BootID)
	}
	if env.KDF != "argon2id" {
		t.Fatalf("expected KDF argon2id, got %q", env.KDF)
	}
	if len(env.Salt) != saltSize {
		t.Fatalf("expected salt size %d, got %d", saltSize, len(env.Salt))
	}
	if len(env.Ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}
	if env.PINMaxFailures != 5 {
		t.Fatalf("expected PINMaxFailures 5, got %d", env.PINMaxFailures)
	}

	// Open with correct PIN.
	got, updated, err := svc.Open(ctx, testRef, env, testPIN, testBootID)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Material bytes must match.
	if string(got.CacheKey) != string(material.CacheKey) {
		t.Fatalf("CacheKey mismatch: got %q, want %q", got.CacheKey, material.CacheKey)
	}
	if string(got.UserKey) != string(material.UserKey) {
		t.Fatalf("UserKey mismatch: got %q, want %q", got.UserKey, material.UserKey)
	}

	// Updated envelope must have reset failure fields.
	if updated.FailedAttempts != 0 {
		t.Fatalf("expected FailedAttempts 0, got %d", updated.FailedAttempts)
	}
	if !updated.BackoffUntil.IsZero() {
		t.Fatalf("expected zero BackoffUntil, got %v", updated.BackoffUntil)
	}
}

func TestOpenEnvelopeWrongPINRecordsFailure(t *testing.T) {
	svc := New(ServiceConfig{
		TTL:         1 * time.Hour,
		MaxFailures: 2,
		KDFTime:     1,
		KDFMemory:   64,
		KDFThreads:  1,
	})
	ctx := context.Background()

	env, err := svc.Create(ctx, testRef, testMaterial(), testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Wrong PIN.
	material, updated, err := svc.Open(ctx, testRef, env, "wrong-pin", testBootID)
	if err != ErrInvalidPIN {
		t.Fatalf("expected ErrInvalidPIN, got %v", err)
	}
	if material.CacheKey != nil || material.UserKey != nil {
		t.Fatal("expected empty material on wrong PIN")
	}
	if updated.FailedAttempts != 1 {
		t.Fatalf("expected FailedAttempts 1, got %d", updated.FailedAttempts)
	}
	if updated.BackoffUntil.IsZero() {
		t.Fatal("expected non-zero BackoffUntil after wrong PIN")
	}
	if !updated.BackoffUntil.After(env.BackoffUntil) {
		t.Fatal("expected BackoffUntil to be in the future")
	}
}

func TestOpenEnvelopeDeletesAfterMaxFailures(t *testing.T) {
	svc := New(ServiceConfig{
		TTL:         1 * time.Hour,
		MaxFailures: 2,
		KDFTime:     1,
		KDFMemory:   64,
		KDFThreads:  1,
	})
	ctx := context.Background()

	env, err := svc.Create(ctx, testRef, testMaterial(), testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// First wrong attempt.
	_, updated, err := svc.Open(ctx, testRef, env, "wrong-pin", testBootID)
	if err != ErrInvalidPIN {
		t.Fatalf("expected ErrInvalidPIN, got %v", err)
	}
	if updated.ShouldDeleteAfterFailures() {
		t.Fatalf("should not delete yet: attempts=%d max=%d", updated.FailedAttempts, updated.PINMaxFailures)
	}

	// Clear backoff so we can try again immediately.
	updated.BackoffUntil = time.Time{}

	// Second wrong attempt.
	_, updated, err = svc.Open(ctx, testRef, updated, "wrong-pin", testBootID)
	if err != ErrInvalidPIN {
		t.Fatalf("expected ErrInvalidPIN, got %v", err)
	}
	if !updated.ShouldDeleteAfterFailures() {
		t.Fatalf("expected ShouldDeleteAfterFailures true: attempts=%d max=%d", updated.FailedAttempts, updated.PINMaxFailures)
	}
}

func TestOpenEnvelopeAllowsLegacyExpiredEnvelopeInSameBoot(t *testing.T) {
	svc := New(testConfig())
	ctx := context.Background()

	env, err := svc.Create(ctx, testRef, testMaterial(), testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	env.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)

	material, updated, err := svc.Open(ctx, testRef, env, testPIN, testBootID)
	if err != nil {
		t.Fatalf("expected legacy expired envelope to open in same boot, got %v", err)
	}
	defer material.Close()
	if updated.FailedAttempts != 0 {
		t.Fatalf("expected FailedAttempts 0 after successful unlock, got %d", updated.FailedAttempts)
	}
}

func TestOpenEnvelopeRejectsBootChanged(t *testing.T) {
	svc := New(testConfig())
	ctx := context.Background()

	env, err := svc.Create(ctx, testRef, testMaterial(), testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	_, updated, err := svc.Open(ctx, testRef, env, testPIN, "different-boot")
	if err != session.ErrBootChanged {
		t.Fatalf("expected ErrBootChanged, got %v", err)
	}
	// Boot change should not increment failure counter.
	if updated.FailedAttempts != 0 {
		t.Fatalf("expected FailedAttempts 0 after boot change, got %d", updated.FailedAttempts)
	}
}

func TestCreateCancelledContext(t *testing.T) {
	svc := New(testConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := svc.Create(ctx, testRef, testMaterial(), testPIN, testBootID)
	if err != context.Canceled {
		t.Fatalf("Create with cancelled context: expected context.Canceled, got %v", err)
	}
}

func TestOpenCancelledContext(t *testing.T) {
	svc := New(testConfig())

	env, err := svc.Create(context.Background(), testRef, testMaterial(), testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = svc.Open(ctx, testRef, env, testPIN, testBootID)
	if err != context.Canceled {
		t.Fatalf("Open with cancelled context: expected context.Canceled, got %v", err)
	}
}

func TestDefaultTTLDoesNotExpireWithinBootSession(t *testing.T) {
	svc := New(ServiceConfig{})
	ctx := context.Background()

	env, err := svc.Create(ctx, testRef, testMaterial(), testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if !env.ExpiresAt.IsZero() {
		t.Fatalf("default envelope ExpiresAt = %v, want zero for session-long PIN unlock", env.ExpiresAt)
	}
}

func TestOpenEnvelopeRejectsBackoff(t *testing.T) {
	svc := New(testConfig())
	ctx := context.Background()

	env, err := svc.Create(ctx, testRef, testMaterial(), testPIN, testBootID)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Set a backoff in the future.
	env.BackoffUntil = time.Now().UTC().Add(30 * time.Second)

	_, updated, err := svc.Open(ctx, testRef, env, testPIN, testBootID)
	if err != session.ErrPINBackoff {
		t.Fatalf("expected ErrPINBackoff, got %v", err)
	}
	if updated.FailedAttempts != 0 {
		t.Fatalf("expected FailedAttempts 0 during backoff, got %d", updated.FailedAttempts)
	}
}
