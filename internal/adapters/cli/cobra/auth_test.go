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

	coreauth "github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	cerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

type fakeAuthService struct {
	email            string
	password         string
	pin              string
	requireTwoFactor bool
	twoFactorCode    string
	events           chan in.Event
	authStatus       session.AuthStatus
	authStatusErr    error
	loginErr         error
}

func newFakeAuthService() *fakeAuthService {
	return &fakeAuthService{events: make(chan in.Event, 4), authStatus: session.Unauthenticated}
}

func (f *fakeAuthService) Login(_ context.Context, input coreauth.LoginInput) error {
	f.email = input.Email
	f.password = input.Password
	f.pin = input.PIN
	if f.requireTwoFactor && input.TwoFactorPrompt != nil {
		_, code, _, err := input.TwoFactorPrompt(context.Background(), []coreauth.TwoFactorProvider{coreauth.TwoFactorProviderAuthenticator})
		if err != nil {
			return err
		}
		f.twoFactorCode = code
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
		_, code, _, err := prompt(ctx, []coreauth.TwoFactorProvider{coreauth.TwoFactorProviderAuthenticator})
		if err != nil {
			return err
		}
		f.twoFactorCode = code
	}
	return f.Unlock(ctx, email, password)
}
func (f *fakeAuthService) UnlockWithPIN(_ context.Context, email, pin string) error {
	f.email = email
	f.pin = pin
	return nil
}
func (f *fakeAuthService) Lock(context.Context) error { return nil }
func (f *fakeAuthService) Search(context.Context, string, int) ([]vault.ScoredItem, error) {
	return nil, nil
}
func (f *fakeAuthService) Items(context.Context) ([]vault.Item, error)     { return nil, nil }
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

	// Feed email (already in args), password (args), and PIN via stdin.
	stdin := strings.NewReader("1234\n")
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

	stdin := strings.NewReader("1234\n")
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
	// Input: first line is PIN, second line is 2FA code (PIN prompted before Login).
	stdin := strings.NewReader("9999\n123456\n")
	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "us"})
	root.SetIn(stdin)
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	require.NoError(t, root.ExecuteContext(context.Background()))
	require.Equal(t, "123456", fake.twoFactorCode)
	require.Equal(t, "9999", fake.pin)
	require.Equal(t, "me@example.com", fake.email)
	require.Equal(t, "master-password", fake.password)
}

func TestUnlockUsesConfiguredEmailAndPIN(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
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
	fake.authStatus = session.LoggedInLocked
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
	fake.authStatus = session.LoggedInUnlockAvailable
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
	fake.authStatus = session.KeyringUnavailable
	fake.authStatusErr = errors.New("keyring unavailable")
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
	require.Contains(t, err.Error(), "gtk4-layershell-bitwarden login")
}
