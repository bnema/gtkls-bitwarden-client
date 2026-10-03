package app

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	coreerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/session"
)

// recordingCredentials wraps fakeCredentialStore to capture the refs passed to
// delete operations and to inject token-deletion failures.
type recordingCredentials struct {
	*fakeCredentialStore
	refs           []session.AccountRef
	deleteTokenErr error
}

func (r *recordingCredentials) DeleteTokenBundle(ctx context.Context, ref session.AccountRef) error {
	r.refs = append(r.refs, ref)
	if r.deleteTokenErr != nil {
		return r.deleteTokenErr
	}
	return r.fakeCredentialStore.DeleteTokenBundle(ctx, ref)
}

func (r *recordingCredentials) DeleteUnlockEnvelope(ctx context.Context, ref session.AccountRef) error {
	r.refs = append(r.refs, ref)
	return r.fakeCredentialStore.DeleteUnlockEnvelope(ctx, ref)
}

func (r *recordingCredentials) DeletePINProfile(ctx context.Context, ref session.AccountRef) error {
	r.refs = append(r.refs, ref)
	return r.fakeCredentialStore.DeletePINProfile(ctx, ref)
}

func TestForgetAccountDeletesAllCredentials(t *testing.T) {
	cs := &recordingCredentials{fakeCredentialStore: &fakeCredentialStore{}}
	cfg := coreconfig.Default()
	cfg.Bitwarden.Region = coreconfig.RegionSelfHosted
	cfg.Bitwarden.ServerURL = "https://vault.example.test/"
	svc := NewService(Deps{Config: cfg, Credentials: cs})

	require.NoError(t, svc.ForgetAccount(context.Background(), "  User@Example.com "))

	cs.mu.Lock()
	defer cs.mu.Unlock()
	require.Equal(t, 1, cs.checkAvailableCalls)
	require.Equal(t, 1, cs.delEnvCalls)
	require.Equal(t, 1, cs.delTokenCalls)
	require.Equal(t, 1, cs.delPINCalls)
	require.Len(t, cs.refs, 3)
	for _, ref := range cs.refs {
		require.Equal(t, session.AccountRef{Email: "user@example.com", ServerURL: "https://vault.example.test"}, ref)
	}

	svc.mu.Lock()
	defer svc.mu.Unlock()
	require.Equal(t, auth.LockStateLocked, svc.state)
}

func TestForgetAccountRequiresEmail(t *testing.T) {
	cs := &fakeCredentialStore{}
	svc := NewService(Deps{Config: coreconfig.Default(), Credentials: cs})

	require.Error(t, svc.ForgetAccount(context.Background(), "  "))

	cs.mu.Lock()
	defer cs.mu.Unlock()
	require.Zero(t, cs.checkAvailableCalls)
	require.Zero(t, cs.delEnvCalls+cs.delTokenCalls+cs.delPINCalls)
}

func TestForgetAccountStopsWhenKeyringUnavailable(t *testing.T) {
	cs := &fakeCredentialStore{checkAvailableErr: coreerrors.ErrUnsupported}
	svc := NewService(Deps{Config: coreconfig.Default(), Credentials: cs})

	err := svc.ForgetAccount(context.Background(), "user@example.com")
	require.ErrorIs(t, err, coreerrors.ErrUnsupported)

	cs.mu.Lock()
	defer cs.mu.Unlock()
	require.Zero(t, cs.delEnvCalls+cs.delTokenCalls+cs.delPINCalls, "nothing may be deleted when the keyring check fails")
}

func TestForgetAccountWithoutCredentialStore(t *testing.T) {
	svc := NewService(Deps{Config: coreconfig.Default()})
	require.ErrorIs(t, svc.ForgetAccount(context.Background(), "user@example.com"), coreerrors.ErrUnsupported)
}

func TestForgetAccountReportsDeleteFailures(t *testing.T) {
	boom := errors.New("boom")

	t.Run("envelope", func(t *testing.T) {
		cs := &fakeCredentialStore{deleteEnvelopeErr: boom}
		svc := NewService(Deps{Config: coreconfig.Default(), Credentials: cs})
		require.ErrorIs(t, svc.ForgetAccount(context.Background(), "user@example.com"), boom)
		require.Zero(t, cs.delTokenCalls, "later deletes must not run after a failure")
	})
	t.Run("token", func(t *testing.T) {
		cs := &recordingCredentials{fakeCredentialStore: &fakeCredentialStore{}, deleteTokenErr: boom}
		svc := NewService(Deps{Config: coreconfig.Default(), Credentials: cs})
		require.ErrorIs(t, svc.ForgetAccount(context.Background(), "user@example.com"), boom)
		require.Zero(t, cs.delPINCalls)
	})
	t.Run("pin profile", func(t *testing.T) {
		cs := &fakeCredentialStore{deletePINErr: boom}
		svc := NewService(Deps{Config: coreconfig.Default(), Credentials: cs})
		require.ErrorIs(t, svc.ForgetAccount(context.Background(), "user@example.com"), boom)
	})
}
