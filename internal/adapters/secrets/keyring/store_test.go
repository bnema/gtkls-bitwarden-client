package keyring

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	session "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
)

// ---------------------------------------------------------------------------
// Fake backend for tests
// ---------------------------------------------------------------------------

type backendOp struct {
	Op      string // "set", "get", "delete"
	Service string
	User    string
}

type fakeBackend struct {
	mu    sync.Mutex
	data  map[[2]string]string // key: [service, user]
	calls []backendOp
	err   error // if non-nil, all operations fail with this error
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{data: make(map[[2]string]string)}
}

func (f *fakeBackend) Set(service, user, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, backendOp{Op: "set", Service: service, User: user})
	if f.err != nil {
		return f.err
	}
	f.data[[2]string{service, user}] = password
	return nil
}

func (f *fakeBackend) Get(service, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, backendOp{Op: "get", Service: service, User: user})
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.data[[2]string{service, user}]
	if !ok {
		return "", errNotFound
	}
	return v, nil
}

func (f *fakeBackend) Delete(service, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, backendOp{Op: "delete", Service: service, User: user})
	if f.err != nil {
		return f.err
	}
	k := [2]string{service, user}
	if _, ok := f.data[k]; !ok {
		return errNotFound
	}
	delete(f.data, k)
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func ref(t *testing.T, email, serverURL string) session.AccountRef {
	t.Helper()
	return session.AccountRef{Email: email, ServerURL: serverURL}
}

func TestStoreTokenBundleLookupIgnoresAccountID(t *testing.T) {
	fake := newFakeBackend()
	store := NewForBackend(fake)
	ctx := context.Background()

	acctRef := ref(t, "user@example.com", "https://vault.example.com")
	bundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        "user@example.com",
		ServerURL:    "https://vault.example.com",
		AccessToken:  []byte("access-token-value"),
		RefreshToken: []byte("refresh-token-value"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	err := store.SaveTokenBundle(ctx, acctRef, bundle)
	require.NoError(t, err, "SaveTokenBundle should succeed")

	loaded, err := store.LoadTokenBundle(ctx, acctRef)
	require.NoError(t, err, "LoadTokenBundle should succeed")

	// AccountID and RefreshToken must be preserved.
	assert.Equal(t, bundle.AccountID, loaded.AccountID, "AccountID should be preserved")
	assert.Equal(t, bundle.RefreshToken, loaded.RefreshToken, "RefreshToken should match")

	// Verify no backend key contains "acct-1".
	fake.mu.Lock()
	for key := range fake.data {
		assert.NotContains(t, key[0], "acct-1", "service should not contain AccountID")
		assert.NotContains(t, key[1], "acct-1", "user should not contain AccountID")
	}
	fake.mu.Unlock()
}

func TestStoreUnlockEnvelopeRoundTrip(t *testing.T) {
	fake := newFakeBackend()
	store := NewForBackend(fake)
	ctx := context.Background()

	acctRef := ref(t, "alice@example.com", "https://bitwarden.example.com")
	now := time.Date(2025, 7, 15, 10, 0, 0, 0, time.UTC)

	envelope := session.UnlockEnvelope{
		Version:        1,
		Account:        acctRef,
		AccountID:      "acc-99",
		BootID:         "boot-xyz",
		ExpiresAt:      now.Add(24 * time.Hour),
		KDF:            "argon2id",
		KDFTime:        3,
		KDFMemory:      64,
		KDFThreads:     4,
		Salt:           []byte("saltsalt"),
		Ciphertext:     []byte("ciphertext-data"),
		FailedAttempts: 0,
		PINMaxFailures: 5,
	}

	err := store.SaveUnlockEnvelope(ctx, acctRef, envelope)
	require.NoError(t, err, "SaveUnlockEnvelope should succeed")

	loaded, err := store.LoadUnlockEnvelope(ctx, acctRef)
	require.NoError(t, err, "LoadUnlockEnvelope should succeed")

	assert.Equal(t, envelope.Version, loaded.Version)
	assert.Equal(t, envelope.Account, loaded.Account)
	assert.Equal(t, envelope.AccountID, loaded.AccountID)
	assert.Equal(t, envelope.BootID, loaded.BootID)
	assert.True(t, envelope.ExpiresAt.Equal(loaded.ExpiresAt))
	assert.Equal(t, envelope.KDF, loaded.KDF)
	assert.Equal(t, envelope.KDFTime, loaded.KDFTime)
	assert.Equal(t, envelope.KDFMemory, loaded.KDFMemory)
	assert.Equal(t, envelope.KDFThreads, loaded.KDFThreads)
	assert.Equal(t, envelope.Salt, loaded.Salt)
	assert.Equal(t, envelope.Ciphertext, loaded.Ciphertext)
	assert.Equal(t, envelope.FailedAttempts, loaded.FailedAttempts)
	assert.Equal(t, envelope.PINMaxFailures, loaded.PINMaxFailures)
	assert.True(t, envelope.BackoffUntil.Equal(loaded.BackoffUntil))
}

func TestCheckAvailableTouchesBackendBeforeLogin(t *testing.T) {
	fake := newFakeBackend()
	store := NewForBackend(fake)
	ctx := context.Background()

	err := store.CheckAvailable(ctx)
	require.NoError(t, err, "CheckAvailable should succeed on working backend")

	fake.mu.Lock()
	calls := make([]backendOp, len(fake.calls))
	copy(calls, fake.calls)
	fake.mu.Unlock()

	// Must have at least set, get, delete on the probe key.
	require.GreaterOrEqual(t, len(calls), 3, "expected at least 3 backend calls")

	assert.Equal(t, "set", calls[0].Op, "first call should be Set")
	assert.Equal(t, serviceProbe, calls[0].Service)
	assert.Equal(t, probeUser, calls[0].User)

	assert.Equal(t, "get", calls[1].Op, "second call should be Get")
	assert.Equal(t, serviceProbe, calls[1].Service)
	assert.Equal(t, probeUser, calls[1].User)

	assert.Equal(t, "delete", calls[2].Op, "third call should be Delete")
	assert.Equal(t, serviceProbe, calls[2].Service)
	assert.Equal(t, probeUser, calls[2].User)
}

func TestCheckAvailableReturnsSecretServiceRequiredOnBackendError(t *testing.T) {
	fake := newFakeBackend()
	fake.err = errors.New("dbus connection refused")
	store := NewForBackend(fake)
	ctx := context.Background()

	err := store.CheckAvailable(ctx)
	require.Error(t, err, "CheckAvailable should fail on backend error")
	assert.Contains(t, err.Error(), "Secret Service is required",
		"error message should mention Secret Service")
}

func TestLoadMissingMapsNotFound(t *testing.T) {
	fake := newFakeBackend()
	store := NewForBackend(fake)
	ctx := context.Background()

	acctRef := ref(t, "missing@example.com", "https://vault.example.com")

	_, err := store.LoadTokenBundle(ctx, acctRef)
	require.Error(t, err, "LoadTokenBundle should fail for missing credential")
	assert.True(t, errors.Is(err, coreerrors.ErrNotFound),
		"error should be ErrNotFound")

	_, err = store.LoadUnlockEnvelope(ctx, acctRef)
	require.Error(t, err, "LoadUnlockEnvelope should fail for missing credential")
	assert.True(t, errors.Is(err, coreerrors.ErrNotFound),
		"error should be ErrNotFound")
}
