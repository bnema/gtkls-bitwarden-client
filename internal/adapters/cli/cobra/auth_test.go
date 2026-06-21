package cobra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coreauth "github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	cerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/session"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
)

// TODO: Replace fakeAuthService with a generated mock if this app repo adopts
// mockery configuration for inbound ports.
type fakeAuthService struct {
	email               string
	password            string
	pin                 string
	requireTwoFactor    bool
	twoFactorCode       string
	twoFactorRemember   bool
	events              chan in.Event
	authStatus          session.AuthStatus
	authStatusErr       error
	authStatusDetail    session.AuthStatusDetail
	authStatusDetailErr error
	loginErr            error
}

func newFakeAuthService() *fakeAuthService {
	return &fakeAuthService{events: make(chan in.Event, 4), authStatus: session.Unauthenticated}
}

func (f *fakeAuthService) Login(_ context.Context, input coreauth.LoginInput) error {
	f.email = input.Email
	f.password = input.Password
	f.pin = input.PIN
	if f.requireTwoFactor && input.TwoFactorPrompt != nil {
		_, code, remember, err := input.TwoFactorPrompt(context.Background(), []coreauth.TwoFactorProvider{coreauth.TwoFactorProviderAuthenticator})
		if err != nil {
			return err
		}
		f.twoFactorCode = code
		f.twoFactorRemember = remember
	}
	if f.loginErr != nil {
		return f.loginErr
	}
	return nil
}
func (f *fakeAuthService) Unlock(_ context.Context, email, password string) error {
	f.email = email
	f.password = password
	return nil
}
func (f *fakeAuthService) UnlockWithTwoFactor(ctx context.Context, email, password string, prompt coreauth.TwoFactorPrompt) error {
	if f.requireTwoFactor && prompt != nil {
		_, code, remember, err := prompt(ctx, []coreauth.TwoFactorProvider{coreauth.TwoFactorProviderAuthenticator})
		if err != nil {
			return err
		}
		f.twoFactorCode = code
		f.twoFactorRemember = remember
	}
	return f.Unlock(ctx, email, password)
}
func (f *fakeAuthService) UnlockWithPIN(_ context.Context, email, pin string) error {
	f.email = email
	f.pin = pin
	return nil
}
func (f *fakeAuthService) UnlockAndCreateEnvelope(ctx context.Context, email, password, pin string, prompt coreauth.TwoFactorPrompt) error {
	return f.UnlockWithPIN(ctx, email, pin)
}
func (f *fakeAuthService) RenewUnlockEnvelope(_ context.Context, _ coreauth.RenewEnvelopeInput) error {
	return nil
}
func (f *fakeAuthService) Lock(context.Context) error     { return nil }
func (f *fakeAuthService) SoftLock(context.Context) error { return nil }
func (f *fakeAuthService) SetBackgroundSyncSuspended(context.Context, bool) error {
	return nil
}
func (f *fakeAuthService) SyncNow(context.Context) error              { return nil }
func (f *fakeAuthService) HardLock(_ context.Context, _ string) error { return nil }
func (f *fakeAuthService) Search(context.Context, string, int) ([]vault.ScoredItem, error) {
	return nil, nil
}
func (f *fakeAuthService) Items(context.Context) ([]vault.Item, error) { return nil, nil }
func (f *fakeAuthService) Conflicts(context.Context) ([]coresync.Conflict, error) {
	return nil, nil
}
func (f *fakeAuthService) ConflictDetail(context.Context, string) (coresync.ConflictDetail, error) {
	return coresync.ConflictDetail{}, nil
}
func (f *fakeAuthService) Get(context.Context, string) (vault.Item, error) { return vault.Item{}, nil }
func (f *fakeAuthService) Create(_ context.Context, item vault.Item) (vault.Item, error) {
	return item, nil
}
func (f *fakeAuthService) Update(_ context.Context, _ string, item vault.Item) (vault.Item, error) {
	return item, nil
}
func (f *fakeAuthService) Trash(context.Context, string) error { return nil }
func (f *fakeAuthService) Restore(context.Context, string) (vault.Item, error) {
	return vault.Item{}, nil
}
func (f *fakeAuthService) Delete(context.Context, string) error { return nil }
func (f *fakeAuthService) ListAttachments(context.Context, string) ([]vault.Attachment, error) {
	return nil, nil
}
func (f *fakeAuthService) DownloadAttachment(context.Context, string, string, io.Writer) error {
	return nil
}
func (f *fakeAuthService) UploadAttachment(context.Context, string, string, int64, io.Reader) (vault.Attachment, error) {
	return vault.Attachment{}, nil
}
func (f *fakeAuthService) DeleteAttachment(context.Context, string, string) error { return nil }
func (f *fakeAuthService) ResolveConflict(context.Context, string, coresync.ConflictResolution) error {
	return nil
}
func (f *fakeAuthService) Config() *coreconfig.Config                             { return coreconfig.Default() }
func (f *fakeAuthService) UpdateConfig(context.Context, *coreconfig.Config) error { return nil }
func (f *fakeAuthService) Events() <-chan in.Event                                { return f.events }
func (f *fakeAuthService) Shutdown(context.Context) error {
	close(f.events)
	return nil
}
func (f *fakeAuthService) AuthStatus(_ context.Context, _ string) (session.AuthStatus, error) {
	return f.authStatus, f.authStatusErr
}
func (f *fakeAuthService) AuthStatusDetail(_ context.Context, _ string) (session.AuthStatusDetail, error) {
	return f.authStatusDetail, f.authStatusDetailErr
}

func TestLoginDoesNotPrintBWSessionAndRequiresPIN(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	// Feed email (already in args), password (args), PIN, and PIN confirmation via stdin.
	stdin := strings.NewReader("1234\n1234\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "us"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err := root.ExecuteContext(context.Background())
	require.NoError(t, err)

	// Verify fake service received correct credentials.
	require.Equal(t, "me@example.com", fake.email)
	require.Equal(t, "master-password", fake.password)
	require.Equal(t, "1234", fake.pin)

	// Output should NOT contain a session key or BW_SESSION.
	output := out.String()
	require.NotContains(t, output, "BW_SESSION", "output must not contain BW_SESSION")
	require.NotContains(t, output, "session", "output must not mention session key")
	require.Contains(t, output, "login ok")

	// Config should save the email.
	getOut, err := executeCmd(t, opts, []string{"config", "get", "bitwarden.email"})
	require.NoError(t, err)
	require.Equal(t, "me@example.com\n", getOut)
}

func TestLoginSavesRegionAndSelfHostedServerURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	stdin := strings.NewReader("1234\n1234\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "self_hosted", "--server-url", "https://bitwarden.example.com"})
	root.SetIn(stdin)
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))

	err := root.ExecuteContext(context.Background())
	require.NoError(t, err)

	region, err := executeCmd(t, opts, []string{"config", "get", "bitwarden.region"})
	require.NoError(t, err)
	require.Equal(t, "self_hosted\n", region)
	serverURL, err := executeCmd(t, opts, []string{"config", "get", "bitwarden.server_url"})
	require.NoError(t, err)
	require.Equal(t, "https://bitwarden.example.com\n", serverURL)
}

func TestLoginRejectsInvalidRegion(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: configPath}

	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "mars"})
	root.SetIn(strings.NewReader(""))
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))

	err := root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported region")
}

func TestLoginPromptsForAuthenticatorCode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.requireTwoFactor = true
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}
	// Input: PIN, PIN confirmation, then 2FA code.
	stdin := strings.NewReader("9999\n9999\n123456\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "us"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	require.NoError(t, root.ExecuteContext(context.Background()))
	require.Equal(t, "123456", fake.twoFactorCode)
	require.True(t, fake.twoFactorRemember, "login should implicitly remember the device after successful 2FA")
	require.Equal(t, "9999", fake.pin)
	require.Equal(t, "me@example.com", fake.email)
	require.Equal(t, "master-password", fake.password)
}

func TestUnlockUsesConfiguredEmailAndPIN(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:              session.LoggedInUnlockAvailable,
		Reason:              session.AuthReasonSoftUnlockAvailable,
		HasToken:            true,
		HasPINProfile:       true,
		HasEnvelope:         true,
		EnvelopeValid:       true,
		SoftUnlockAvailable: true,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "1234", "--raw", "--no-sync"})
	outBuf := new(bytes.Buffer)
	root.SetOut(outBuf)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.NoError(t, err)
	require.Equal(t, "me@example.com", fake.email)
	require.Equal(t, "1234", fake.pin, "expected PIN 1234 to be passed to UnlockWithPIN")

	// Output should not contain BW_SESSION or base64 session key.
	output := outBuf.String()
	require.NotContains(t, output, "BW_SESSION", "unlock output must not contain BW_SESSION")
	require.Contains(t, output, "unlock ok")
}

func TestUnlockPromptsPINFromStdin(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:              session.LoggedInUnlockAvailable,
		Reason:              session.AuthReasonSoftUnlockAvailable,
		HasToken:            true,
		HasPINProfile:       true,
		HasEnvelope:         true,
		EnvelopeValid:       true,
		SoftUnlockAvailable: true,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	// Provide PIN via stdin (no arg, no env/file).
	stdin := strings.NewReader("9999\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "--raw", "--no-sync"})
	root.SetIn(stdin)
	outBuf := new(bytes.Buffer)
	root.SetOut(outBuf)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.NoError(t, err)
	require.Equal(t, "9999", fake.pin, "expected PIN from stdin to be passed to UnlockWithPIN")
	require.Equal(t, "me@example.com", fake.email)
	require.Contains(t, outBuf.String(), "unlock ok")
}

func TestStatusReportsLockedWhenEmailConfigured(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:        session.LoggedInLocked,
		Reason:        session.AuthReasonNoEnvelope,
		HasToken:      true,
		HasPINProfile: true,
		HasEnvelope:   false,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	out, err := executeCmd(t, opts, []string{"status"})
	require.NoError(t, err)

	var resp statusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.Equal(t, "me@example.com", resp.UserEmail)
	require.Equal(t, string(session.LoggedInLocked), resp.Status)
}

func TestStatusReportsAuthStatusFromService(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:              session.LoggedInUnlockAvailable,
		Reason:              session.AuthReasonSoftUnlockAvailable,
		HasToken:            true,
		HasPINProfile:       true,
		HasEnvelope:         true,
		EnvelopeValid:       true,
		SoftUnlockAvailable: true,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	out, err := executeCmd(t, opts, []string{"status"})
	require.NoError(t, err)

	var resp statusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.Equal(t, "me@example.com", resp.UserEmail)
	require.Equal(t, string(session.LoggedInUnlockAvailable), resp.Status)
}

func TestStatusReportsKeyringUnavailable(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status: session.KeyringUnavailable,
		Reason: session.AuthReasonKeyringUnavailable,
	}
	fake.authStatusDetailErr = errors.New("keyring unavailable")
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	out, err := executeCmd(t, opts, []string{"status"})
	require.NoError(t, err)

	var resp statusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.Equal(t, "me@example.com", resp.UserEmail)
	require.Equal(t, string(session.KeyringUnavailable), resp.Status)
}

func TestLoginFailsOnKeyringUnavailable(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := &fakeAuthService{
		events:     make(chan in.Event, 4),
		authStatus: session.KeyringUnavailable,
		authStatusErr: &cerrors.Error{
			Kind:    cerrors.KindValidation,
			Op:      "credentials.CheckAvailable",
			Message: "secret service not available",
		},
		authStatusDetail: session.AuthStatusDetail{
			Status: session.KeyringUnavailable,
			Reason: session.AuthReasonKeyringUnavailable,
		},
		authStatusDetailErr: &cerrors.Error{
			Kind:    cerrors.KindValidation,
			Op:      "credentials.CheckAvailable",
			Message: "secret service not available",
		},
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	// stdin has no PIN content — the command must fail before consuming stdin.
	stdin := strings.NewReader("")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "us"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err := root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "secret service not available")

	// Output should NOT contain "login ok" or BW_SESSION.
	output := out.String()
	require.NotContains(t, output, "login ok", "output must not contain login ok")
	require.NotContains(t, output, "BW_SESSION", "output must not contain BW_SESSION")
}

func TestLayerShellUnavailableSuggestsCLIAuth(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return newFakeAuthService(), nil
		},
		RunOverlay: func(context.Context, in.AppService) error {
			return errors.New("gtk overlay: layer-shell is not available")
		},
	}

	_, err := executeCmd(t, opts, []string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtkls-bitwarden-client login")
}

// TestUnlockDoesNotConsumePINStdinWhenKeyringUnavailable verifies that
// unlock fails fast on keyring-unavailable without consuming PIN from stdin.
func TestUnlockDoesNotConsumePINStdinWhenKeyringUnavailable(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := &fakeAuthService{
		events: make(chan in.Event, 4),
		authStatusDetail: session.AuthStatusDetail{
			Status: session.KeyringUnavailable,
			Reason: session.AuthReasonKeyringUnavailable,
		},
		authStatusDetailErr: &cerrors.Error{
			Kind:    cerrors.KindValidation,
			Op:      "credentials.CheckAvailable",
			Message: "secret service not available",
		},
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	// Set up email in config.
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	// Provide PIN via stdin — it should NOT be consumed since keyring check
	// fails first.
	stdin := strings.NewReader("9999\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "--raw", "--no-sync"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "secret service is required for unlock")

	// Verify PIN was NOT consumed (should not have been passed to UnlockWithPIN).
	require.Empty(t, fake.pin, "PIN should not be consumed when keyring is unavailable")
}

// TestUnlockDoesNotConsumePINWhenUnauthenticated verifies that
// unlock fails fast on unauthenticated without consuming PIN from stdin.
func TestUnlockDoesNotConsumePINWhenUnauthenticated(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status: session.Unauthenticated,
		Reason: session.AuthReasonNoToken,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	// Provide PIN via stdin — it should NOT be consumed since status check fails first.
	stdin := strings.NewReader("9999\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "--raw", "--no-sync"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not logged in")

	// Verify PIN was NOT consumed.
	require.Empty(t, fake.pin, "PIN should not be consumed when unauthenticated")
}

// TestUnlockDoesNotConsumePINWhenLoggedInLocked verifies that
// unlock fails fast on LoggedInLocked without consuming PIN from stdin.
func TestUnlockDoesNotConsumePINWhenLoggedInLocked(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:        session.LoggedInLocked,
		Reason:        session.AuthReasonNoEnvelope,
		HasToken:      true,
		HasPINProfile: true,
		HasEnvelope:   false,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	// Provide PIN via stdin — it should NOT be consumed since status check fails first.
	stdin := strings.NewReader("9999\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "--raw", "--no-sync"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no unlock envelope")

	// Verify PIN was NOT consumed.
	require.Empty(t, fake.pin, "PIN should not be consumed when logged-in-locked")
}

// TestUnlockAllowsLegacyExpiredEnvelope verifies that legacy expired envelope
// status still allows PIN-only unlock in the same boot/session.
func TestUnlockAllowsLegacyExpiredEnvelope(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:        session.LoggedInLocked,
		Reason:        session.AuthReasonEnvelopeExpired,
		HasToken:      true,
		HasPINProfile: true,
		HasEnvelope:   true,
		EnvelopeValid: false,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	stdin := strings.NewReader("9999\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "--raw", "--no-sync"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.NoError(t, err)
	require.Equal(t, "9999", fake.pin, "PIN should be consumed for legacy expired envelope unlock")
}

// TestUnlockFailsWhenBootChanged verifies that unlock fails fast
// with guidance when the system boot ID changed.
func TestUnlockFailsWhenBootChanged(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:        session.LoggedInLocked,
		Reason:        session.AuthReasonBootChanged,
		HasToken:      true,
		HasPINProfile: true,
		HasEnvelope:   true,
		EnvelopeValid: false,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	stdin := strings.NewReader("9999\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "--raw", "--no-sync"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "boot changed")

	// Verify PIN was NOT consumed.
	require.Empty(t, fake.pin, "PIN should not be consumed when boot changed")
}

// TestStatusReportsDetailFields verifies that status exposes
// reason, hasPinProfile, hasEnvelope, envelopeValid, and softUnlockAvailable.
func TestStatusReportsDetailFields(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:              session.LoggedInUnlockAvailable,
		Reason:              session.AuthReasonSoftUnlockAvailable,
		HasToken:            true,
		HasPINProfile:       true,
		HasEnvelope:         true,
		EnvelopeValid:       true,
		SoftUnlockAvailable: true,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	out, err := executeCmd(t, opts, []string{"status"})
	require.NoError(t, err)

	var resp statusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.Equal(t, "me@example.com", resp.UserEmail)
	require.Equal(t, string(session.LoggedInUnlockAvailable), resp.Status)
	require.Equal(t, string(session.AuthReasonSoftUnlockAvailable), resp.Reason)
	require.True(t, resp.HasPinProfile)
	require.True(t, resp.HasEnvelope)
	require.True(t, resp.EnvelopeValid)
	require.True(t, resp.SoftUnlockAvailable)
}

// TestStatusReportsLockedDetail verifies that status reports correct
// detail fields when the vault is locked with a reason.
func TestStatusReportsLockedDetail(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:        session.LoggedInLocked,
		Reason:        session.AuthReasonNoEnvelope,
		HasToken:      true,
		HasPINProfile: true,
		HasEnvelope:   false,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	out, err := executeCmd(t, opts, []string{"status"})
	require.NoError(t, err)

	var resp statusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.Equal(t, string(session.LoggedInLocked), resp.Status)
	require.Equal(t, string(session.AuthReasonNoEnvelope), resp.Reason)
	require.True(t, resp.HasPinProfile, "hasPinProfile should be true")
	require.False(t, resp.HasEnvelope, "hasEnvelope should be false")
	require.False(t, resp.EnvelopeValid, "envelopeValid should be false")
	require.False(t, resp.SoftUnlockAvailable, "softUnlockAvailable should be false")
}

// TestStatusNoEmailReportsDefaultDetail verifies that status without
// a configured email reports unauthenticated with zero detail fields.
func TestStatusNoEmailReportsDefaultDetail(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: configPath}

	out, err := executeCmd(t, opts, []string{"status"})
	require.NoError(t, err)

	var resp statusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.Equal(t, string(session.Unauthenticated), resp.Status)
	require.Equal(t, "", resp.Reason)
	require.False(t, resp.HasPinProfile)
	require.False(t, resp.HasEnvelope)
	require.False(t, resp.EnvelopeValid)
	require.False(t, resp.SoftUnlockAvailable)
}

// TestUnlockFailsWhenPINBackoff verifies that unlock fails fast
// with guidance when PIN backoff is active.
func TestUnlockFailsWhenPINBackoff(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	fake.authStatusDetail = session.AuthStatusDetail{
		Status:        session.LoggedInLocked,
		Reason:        session.AuthReasonPINBackoff,
		HasToken:      true,
		HasPINProfile: true,
		HasEnvelope:   true,
		EnvelopeValid: false,
	}
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	stdin := strings.NewReader("9999\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"unlock", "--raw", "--no-sync"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	err = root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many PIN attempts")

	// Verify PIN was NOT consumed.
	require.Empty(t, fake.pin, "PIN should not be consumed during backoff")
}

// TestLoginRejectsMismatchedPINConfirmation verifies that interactive PIN
// entry during login rejects mismatched confirmation.
func TestLoginRejectsMismatchedPINConfirmation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	// PIN "1234" and confirmation "5678" don't match.
	stdin := strings.NewReader("1234\n5678\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "us"})
	root.SetIn(stdin)
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))

	err := root.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "PINs do not match")

	// Login should NOT have been called on the service.
	require.Empty(t, fake.pin, "PIN should not be forwarded when confirmation mismatches")
}
