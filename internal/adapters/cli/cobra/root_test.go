package cobra

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	adapterlogging "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/logging"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/app"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

// executeCmd runs the root command with the given args and returns stdout/stderr.
func executeCmd(t *testing.T, opts Options, args []string) (string, error) {
	t.Helper()
	out, stderr, err := executeCmdWithContext(t, context.Background(), opts, args)
	return out + stderr, err
}

func executeCmdWithContext(t *testing.T, ctx context.Context, opts Options, args []string) (string, string, error) {
	t.Helper()
	root := NewRootCommand(opts)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	return stdout.String(), stderr.String(), err
}

func TestRootCommandPrintsVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	called := false
	opts := Options{
		Version:    "v0.1.0-test",
		ConfigPath: path,
		RunOverlay: func(_ context.Context, _ in.AppService) error {
			called = true
			return nil
		},
	}

	out, err := executeCmd(t, opts, []string{})
	require.NoError(t, err)
	assert.Contains(t, out, "gtk4-layershell-bitwarden v0.1.0-test")
	assert.True(t, called, "RunOverlay should have been called")
}

func TestRootCommandLifecycleLogsUseContext(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	ctx, cleanup, meta, err := adapterlogging.NewContextFromEnv(context.Background(), "v0.1.0-test")
	require.NoError(t, err)
	cleanupPending := true
	defer func() {
		if cleanupPending {
			cleanup()
		}
	}()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("[bitwarden]\nemail = 'test@example.com'\n"), 0o600))

	composeCalled := false
	overlayCalled := false
	opts := Options{
		Version:    "v0.1.0-test",
		ConfigPath: path,
		ComposeService: func(ctx context.Context, cfg *coreconfig.Config, cachePath, outboxPath string) (in.AppService, error) {
			composeCalled = true
			require.NotNil(t, ctx)
			require.NotNil(t, cfg)
			require.NotEmpty(t, cachePath)
			require.NotEmpty(t, outboxPath)
			return app.NewService(app.Deps{Config: cfg}), nil
		},
		RunOverlay: func(ctx context.Context, svc in.AppService) error {
			overlayCalled = true
			require.NotNil(t, ctx)
			require.NotNil(t, svc)
			return nil
		},
	}

	stdout, stderr, err := executeCmdWithContext(t, ctx, opts, []string{})
	require.NoError(t, err)
	require.True(t, composeCalled, "ComposeService should have been called")
	require.True(t, overlayCalled, "RunOverlay should have been called")

	for _, stream := range []string{stdout, stderr} {
		assert.NotContains(t, stream, "root command started")
		assert.NotContains(t, stream, "config loaded")
		assert.NotContains(t, stream, "service composition started")
		assert.NotContains(t, stream, "service composition finished")
		assert.NotContains(t, stream, "overlay started")
		assert.NotContains(t, stream, "overlay finished")
	}

	cleanup()
	cleanupPending = false
	data, err := os.ReadFile(meta.Path)
	require.NoError(t, err)
	logs := string(data)
	assert.Contains(t, logs, "root command started")
	assert.Contains(t, logs, "config loaded")
	assert.Contains(t, logs, "service composition started")
	assert.Contains(t, logs, "service composition finished")
	assert.Contains(t, logs, "overlay started")
	assert.Contains(t, logs, "overlay finished")
	assert.NotContains(t, logs, "test@example.com")
}

func TestRootCommandFailsOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	// Create an invalid config file (bad scale, no email)
	// With bad scale AND missing email, Load returns the scale error
	// (since only missing email is tolerated alone)
	invalidCfg := `[appearance]
ui_scale = 5.0
`
	err := os.WriteFile(path, []byte(invalidCfg), 0600)
	require.NoError(t, err)

	opts := Options{Version: "v0.1.0", ConfigPath: path}
	_, err = executeCmd(t, opts, []string{})
	require.Error(t, err)
	// Root command wraps with "config load:" which comes from Load's error
	assert.Contains(t, err.Error(), "config load")
}

func TestRootCommandRunOverlayNotCalledOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	invalidCfg := `[appearance]
ui_scale = 5.0
`
	err := os.WriteFile(path, []byte(invalidCfg), 0600)
	require.NoError(t, err)

	called := false
	opts := Options{
		Version:    "v0.1.0",
		ConfigPath: path,
		RunOverlay: func(_ context.Context, _ in.AppService) error {
			called = true
			return nil
		},
	}

	_, err = executeCmd(t, opts, []string{})
	require.Error(t, err)
	assert.False(t, called, "RunOverlay should NOT be called on invalid config")
}

func TestConfigPathPrintsTempPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	out, err := executeCmd(t, opts, []string{"config", "path"})
	require.NoError(t, err)
	assert.Contains(t, out, path)
}

func TestConfigGetReturnsValueAfterSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	// Set email
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "test@example.com"})
	require.NoError(t, err)

	// Get email
	out, err := executeCmd(t, opts, []string{"config", "get", "bitwarden.email"})
	require.NoError(t, err)
	assert.Equal(t, "test@example.com\n", out)
}

func TestConfigValidateFailsWithNoEmail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	// First set a benign value to create the file with defaults (no email)
	_, err := executeCmd(t, opts, []string{"config", "set", "appearance.ui_scale", "1.0"})
	require.NoError(t, err)

	// Validate should fail because no email is set
	_, err = executeCmd(t, opts, []string{"config", "validate"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestConfigValidateSucceedsAfterSettingEmail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	// Set email
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "valid@example.com"})
	require.NoError(t, err)

	// Validate
	out, err := executeCmd(t, opts, []string{"config", "validate"})
	require.NoError(t, err)
	assert.Equal(t, "ok\n", out)
}

func TestConfigSetAndGetMultipleKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	tests := []struct {
		key   string
		value string
	}{
		{"appearance.ui_scale", "2"},
		{"actions.default_primary_action", "copy_username"},
		{"bitwarden.region", "eu"},
	}

	for _, tt := range tests {
		_, err := executeCmd(t, opts, []string{"config", "set", tt.key, tt.value})
		require.NoError(t, err, "set %s", tt.key)

		out, err := executeCmd(t, opts, []string{"config", "get", tt.key})
		require.NoError(t, err, "get %s", tt.key)
		assert.Equal(t, tt.value+"\n", out, "get %s", tt.key)
	}
}

func TestConfigSetInvalidKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	_, err := executeCmd(t, opts, []string{"config", "set", "invalid.key", "value"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported config key")
}

func TestConfigGetInvalidKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	_, err := executeCmd(t, opts, []string{"config", "get", "invalid.key"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported config key")
}

func TestCacheClearRemovesCacheFiles(t *testing.T) {
	dir := t.TempDir()

	// Create dummy cache and outbox files.
	cachePath := filepath.Join(dir, "cache.json")
	outboxPath := filepath.Join(dir, "outbox.json")
	require.NoError(t, os.WriteFile(cachePath, []byte("{}"), 0600))
	require.NoError(t, os.WriteFile(outboxPath, []byte("{}"), 0600))

	// The newCacheCmd is tested directly since RootCommand with config
	// compose would try to create a remote client.
	cmd := newCacheCmd(cachePath, outboxPath)
	cmd.SetArgs([]string{"clear"})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	err := cmd.Execute()
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "cache cleared")

	// Files should be removed.
	require.NoFileExists(t, cachePath)
	require.NoFileExists(t, outboxPath)
}

func TestLogoutPrintsLoggedOut(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	cachePath := filepath.Join(dir, "cache.json")
	outboxPath := filepath.Join(dir, "outbox.json")

	opts := Options{ConfigPath: configPath}
	cmd := newLogoutCmd(opts, cachePath, outboxPath)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "logged out")
}

func TestSyncPrintsMessage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	out, err := executeCmd(t, opts, []string{"sync"})
	require.NoError(t, err)
	assert.Contains(t, out, "sync runs automatically after unlock")
}

func TestSyncWithForcePrintsMessage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	out, err := executeCmd(t, opts, []string{"sync", "--force"})
	require.NoError(t, err)
	assert.Contains(t, out, "force sync requested")
}

func TestRootCommandHandlesMissingConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "config.toml")

	called := false
	opts := Options{
		Version:    "v0.1.0",
		ConfigPath: path,
		RunOverlay: func(_ context.Context, _ in.AppService) error {
			called = true
			return nil
		},
	}

	out, err := executeCmd(t, opts, []string{})
	require.NoError(t, err)
	assert.Contains(t, out, "gtk4-layershell-bitwarden v0.1.0")
	assert.True(t, called, "RunOverlay should have been called with default config")
}

func TestValidateFileNotFoundThenSetAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	// Validate on nonexistent config — Load returns defaults with empty email,
	// then Validate returns ErrEmailRequired
	_, err := executeCmd(t, opts, []string{"config", "validate"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	// Setting email creates config
	_, err = executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "test@example.com"})
	require.NoError(t, err)

	// Validate now passes
	out, err := executeCmd(t, opts, []string{"config", "validate"})
	require.NoError(t, err)
	assert.Equal(t, "ok\n", out)
}

// Test that the config file has proper TOML after set operations
func TestSavedConfigIsValidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "toml@example.com"})
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	// Basic TOML checks - email should appear
	assert.True(t, strings.Contains(content, "email = 'toml@example.com'") ||
		strings.Contains(content, `email = "toml@example.com"`),
		"saved config should contain the email value in TOML format: %s", content)
}

// ---------------------------------------------------------------------------
// Fake credential store for lock/logout tests
// ---------------------------------------------------------------------------

type fakeCredentialStore struct {
	checkAvailableCalls int
	checkAvailableErr   error
	delTokenCalls       int
	delEnvelopeCalls    int
	delPINProfileCalls  int
	delEnvelopeErr      error
	delTokenErr         error
	delPINProfileErr    error
}

func (f *fakeCredentialStore) CheckAvailable(context.Context) error {
	f.checkAvailableCalls++
	return f.checkAvailableErr
}

func (f *fakeCredentialStore) SaveTokenBundle(context.Context, session.AccountRef, session.TokenBundle) error {
	return nil
}
func (f *fakeCredentialStore) LoadTokenBundle(context.Context, session.AccountRef) (session.TokenBundle, error) {
	return session.TokenBundle{}, nil
}
func (f *fakeCredentialStore) DeleteTokenBundle(context.Context, session.AccountRef) error {
	f.delTokenCalls++
	return f.delTokenErr
}
func (f *fakeCredentialStore) SaveUnlockEnvelope(context.Context, session.AccountRef, session.UnlockEnvelope) error {
	return nil
}
func (f *fakeCredentialStore) LoadUnlockEnvelope(context.Context, session.AccountRef) (session.UnlockEnvelope, error) {
	return session.UnlockEnvelope{}, nil
}
func (f *fakeCredentialStore) DeleteUnlockEnvelope(context.Context, session.AccountRef) error {
	f.delEnvelopeCalls++
	return f.delEnvelopeErr
}
func (f *fakeCredentialStore) SavePINProfile(context.Context, session.AccountRef, session.PINProfile) error {
	return nil
}
func (f *fakeCredentialStore) LoadPINProfile(context.Context, session.AccountRef) (session.PINProfile, error) {
	return session.PINProfile{}, nil
}
func (f *fakeCredentialStore) DeletePINProfile(context.Context, session.AccountRef) error {
	f.delPINProfileCalls++
	return f.delPINProfileErr
}

// ---------------------------------------------------------------------------
// Lock tests
// ---------------------------------------------------------------------------

func TestLockDefaultSoftDoesNotDeleteEnvelope(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// Pre-configure email.
	opts := Options{ConfigPath: configPath}
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "test@example.com"})
	require.NoError(t, err)

	fakeStore := &fakeCredentialStore{}
	opts.CredentialStore = fakeStore

	cmd := newLockCmd(opts)
	cmd.SetArgs([]string{})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err = cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "soft lock")
	assert.NotContains(t, output, "BW_SESSION", "output must not contain BW_SESSION")

	// Default lock (soft) should NOT touch the keyring at all.
	assert.Equal(t, 0, fakeStore.checkAvailableCalls, "soft lock should not touch keyring")
	assert.Equal(t, 0, fakeStore.delEnvelopeCalls, "soft lock must not delete envelope")
	assert.Equal(t, 0, fakeStore.delTokenCalls, "soft lock must not delete token")
	assert.Equal(t, 0, fakeStore.delPINProfileCalls, "soft lock must not delete PIN profile")
}

func TestLockHardDeletesUnlockEnvelopeOnly(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// Pre-configure email.
	opts := Options{ConfigPath: configPath}
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "test@example.com"})
	require.NoError(t, err)

	fakeStore := &fakeCredentialStore{}
	opts.CredentialStore = fakeStore

	cmd := newLockCmd(opts)
	cmd.SetArgs([]string{"--hard"})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err = cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Local unlock envelope cleared.")
	assert.NotContains(t, output, "BW_SESSION", "output must not contain BW_SESSION")

	// Unlock envelope should be deleted, token bundle and PIN profile must NOT be touched.
	assert.Equal(t, 1, fakeStore.checkAvailableCalls, "CheckAvailable should be called once")
	assert.Equal(t, 1, fakeStore.delEnvelopeCalls, "DeleteUnlockEnvelope should be called once")
	assert.Equal(t, 0, fakeStore.delTokenCalls, "DeleteTokenBundle must NOT be called")
	assert.Equal(t, 0, fakeStore.delPINProfileCalls, "DeletePINProfile must NOT be called")
}

func TestLockNoEmailPrintsAlreadyLocked(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	fakeStore := &fakeCredentialStore{}
	opts := Options{ConfigPath: configPath, CredentialStore: fakeStore}

	cmd := newLockCmd(opts)
	cmd.SetArgs([]string{})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "already locked")

	// Keyring must NOT be touched when no email is configured.
	assert.Equal(t, 0, fakeStore.checkAvailableCalls, "CheckAvailable must not be called")
	assert.Equal(t, 0, fakeStore.delEnvelopeCalls, "DeleteUnlockEnvelope must not be called")
	assert.Equal(t, 0, fakeStore.delTokenCalls, "DeleteTokenBundle must not be called")
}

func TestLockFailsOnCheckAvailableError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// Pre-configure email.
	opts := Options{ConfigPath: configPath}
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "test@example.com"})
	require.NoError(t, err)

	fakeStore := &fakeCredentialStore{
		checkAvailableErr: assert.AnError,
	}
	opts.CredentialStore = fakeStore

	cmd := newLockCmd(opts)
	cmd.SetArgs([]string{"--hard"})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err = cmd.Execute()
	require.Error(t, err)

	// DeleteUnlockEnvelope must not be reached after CheckAvailable fails.
	assert.Equal(t, 1, fakeStore.checkAvailableCalls, "CheckAvailable should be called once")
	assert.Equal(t, 0, fakeStore.delEnvelopeCalls, "DeleteUnlockEnvelope must not be called after CheckAvailable failure")
}

// ---------------------------------------------------------------------------
// Logout tests
// ---------------------------------------------------------------------------

func TestLogoutDeletesCredentialsAndCacheOutbox(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	cachePath := filepath.Join(dir, "cache.json")
	outboxPath := filepath.Join(dir, "outbox.json")

	// Create dummy cache and outbox files.
	require.NoError(t, os.WriteFile(cachePath, []byte(`{"items":[]}`), 0600))
	require.NoError(t, os.WriteFile(outboxPath, []byte(`{"mutations":[]}`), 0600))

	// Pre-configure email.
	opts := Options{ConfigPath: configPath}
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "test@example.com"})
	require.NoError(t, err)

	fakeStore := &fakeCredentialStore{}
	opts.CredentialStore = fakeStore

	cmd := newLogoutCmd(opts, cachePath, outboxPath)
	cmd.SetArgs([]string{})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err = cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "logged out")

	// Unlock envelope, token bundle, and PIN profile should be deleted.
	assert.Equal(t, 1, fakeStore.checkAvailableCalls, "CheckAvailable should be called once")
	assert.Equal(t, 1, fakeStore.delEnvelopeCalls, "DeleteUnlockEnvelope should be called once")
	assert.Equal(t, 1, fakeStore.delTokenCalls, "DeleteTokenBundle should be called once")
	assert.Equal(t, 1, fakeStore.delPINProfileCalls, "DeletePINProfile should be called once")

	// Cache and outbox files should be removed.
	assert.NoFileExists(t, cachePath, "cache file should be removed")
	assert.NoFileExists(t, outboxPath, "outbox file should be removed")
}

func TestLogoutNoEmailStillClearsCacheAndOutbox(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	cachePath := filepath.Join(dir, "cache.json")
	outboxPath := filepath.Join(dir, "outbox.json")

	// Create dummy cache and outbox files.
	require.NoError(t, os.WriteFile(cachePath, []byte(`{}`), 0600))
	require.NoError(t, os.WriteFile(outboxPath, []byte(`{}`), 0600))

	fakeStore := &fakeCredentialStore{}
	opts := Options{ConfigPath: configPath, CredentialStore: fakeStore}

	cmd := newLogoutCmd(opts, cachePath, outboxPath)
	cmd.SetArgs([]string{})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "logged out")

	// Keyring must NOT be touched when no email is configured.
	assert.Equal(t, 0, fakeStore.checkAvailableCalls, "CheckAvailable must not be called")
	assert.Equal(t, 0, fakeStore.delEnvelopeCalls, "DeleteUnlockEnvelope must not be called")
	assert.Equal(t, 0, fakeStore.delTokenCalls, "DeleteTokenBundle must not be called")

	// Cache and outbox should still be cleared.
	assert.NoFileExists(t, cachePath, "cache file should be removed")
	assert.NoFileExists(t, outboxPath, "outbox file should be removed")
}

func TestLogoutFailsOnKeyringError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	cachePath := filepath.Join(dir, "cache.json")
	outboxPath := filepath.Join(dir, "outbox.json")

	// Create dummy cache and outbox files.
	require.NoError(t, os.WriteFile(cachePath, []byte(`{}`), 0600))
	require.NoError(t, os.WriteFile(outboxPath, []byte(`{}`), 0600))

	// Pre-configure email.
	opts := Options{ConfigPath: configPath}
	_, err := executeCmd(t, opts, []string{"config", "set", "bitwarden.email", "test@example.com"})
	require.NoError(t, err)

	// Credential store returns an error on CheckAvailable.
	fakeStore := &fakeCredentialStore{
		checkAvailableErr: assert.AnError,
	}
	opts.CredentialStore = fakeStore

	cmd := newLogoutCmd(opts, cachePath, outboxPath)
	cmd.SetArgs([]string{})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err = cmd.Execute()
	require.Error(t, err, "logout should fail when keyring is unavailable")
	require.Contains(t, err.Error(), "logout")

	// Output must NOT contain "logged out".
	output := buf.String()
	assert.NotContains(t, output, "logged out", "output must not contain logged out on keyring error")
}
