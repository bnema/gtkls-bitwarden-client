package cobra

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coreauth "github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

type fakeAuthService struct {
	email            string
	password         string
	requireTwoFactor bool
	twoFactorCode    string
	events           chan in.Event
}

func newFakeAuthService() *fakeAuthService {
	return &fakeAuthService{events: make(chan in.Event, 4)}
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

func TestLoginRawUnlocksAndSavesEmail(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	fake := newFakeAuthService()
	opts := Options{
		ConfigPath: configPath,
		ComposeService: func(context.Context, *coreconfig.Config, string, string) (in.AppService, error) {
			return fake, nil
		},
	}

	out, err := executeCmd(t, opts, []string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "us"})
	require.NoError(t, err)
	require.Equal(t, "me@example.com", fake.email)
	require.Equal(t, "master-password", fake.password)

	session, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	require.NoError(t, err)
	require.Len(t, session, 64)

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

	_, err := executeCmd(t, opts, []string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "self_hosted", "--server-url", "https://bitwarden.example.com"})
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

	_, err := executeCmd(t, opts, []string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "mars"})
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
	root := NewRootCommand(opts)
	root.SetArgs([]string{"login", "me@example.com", "master-password", "--raw", "--no-sync", "--region", "us"})
	root.SetIn(strings.NewReader("123456\n"))
	out := new(bytes.Buffer)
	root.SetOut(out)
	root.SetErr(new(bytes.Buffer))

	require.NoError(t, root.ExecuteContext(context.Background()))
	require.Equal(t, "123456", fake.twoFactorCode)
}

func TestUnlockUsesConfiguredEmail(t *testing.T) {
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

	out, err := executeCmd(t, opts, []string{"unlock", "master-password", "--raw", "--no-sync"})
	require.NoError(t, err)
	require.Equal(t, "me@example.com", fake.email)
	require.Equal(t, "master-password", fake.password)
	_, err = base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	require.NoError(t, err)
}

func TestStatusReportsLockedWhenEmailConfigured(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: configPath}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "me@example.com"})
	require.NoError(t, err)

	out, err := executeCmd(t, opts, []string{"status"})
	require.NoError(t, err)

	var status statusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &status))
	require.Equal(t, "me@example.com", status.UserEmail)
	require.Equal(t, "locked", status.Status)
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
