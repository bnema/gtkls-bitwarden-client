package cobra

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// executeCmd runs the root command with the given args and returns stdout/stderr.
func executeCmd(t *testing.T, opts Options, args []string) (string, error) {
	t.Helper()
	root := NewRootCommand(opts)
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestRootCommandPrintsVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{Version: "v0.1.0-test", ConfigPath: path}

	out, err := executeCmd(t, opts, []string{})
	require.NoError(t, err)
	assert.Contains(t, out, "gtk4-layershell-bitwarden v0.1.0-test")
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

func TestCacheClearPrintsNotWired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	out, err := executeCmd(t, opts, []string{"cache", "clear"})
	require.NoError(t, err)
	assert.Contains(t, out, "cache clear not wired yet")
}

func TestLogoutPrintsNotWired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	out, err := executeCmd(t, opts, []string{"logout"})
	require.NoError(t, err)
	assert.Contains(t, out, "logout not wired yet")
}

func TestSyncPrintsNotWired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	out, err := executeCmd(t, opts, []string{"sync"})
	require.NoError(t, err)
	assert.Contains(t, out, "sync not wired yet")
}

func TestSyncWithForcePrintsNotWired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	opts := Options{ConfigPath: path}

	out, err := executeCmd(t, opts, []string{"sync", "--force"})
	require.NoError(t, err)
	assert.Contains(t, out, "sync not wired yet")
}

func TestRootCommandHandlesMissingConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "config.toml")
	opts := Options{Version: "v0.1.0", ConfigPath: path}

	out, err := executeCmd(t, opts, []string{})
	require.NoError(t, err)
	assert.Contains(t, out, "gtk4-layershell-bitwarden v0.1.0")
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
