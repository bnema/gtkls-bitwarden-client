package logging

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bnema/zerowrap"
	"github.com/stretchr/testify/require"
)

type safeCleanup struct {
	once    sync.Once
	cleanup func()
}

func newSafeCleanup(cleanup func()) *safeCleanup {
	return &safeCleanup{cleanup: cleanup}
}

func (c *safeCleanup) Close() {
	c.once.Do(c.cleanup)
}

func TestNewContextFromEnvDefaultsFileOnlyJSON(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	stderrPath, restoreStderr := captureStderrToTempFile(t)
	defer restoreStderr()

	ctx, cleanup, meta, err := NewContextFromEnv(context.Background(), "test-version")
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	logCleanup := newSafeCleanup(cleanup)
	defer logCleanup.Close()

	expectedPath := filepath.Join(stateHome, AppName, "logs", AppName+".log")
	require.Equal(t, LogMeta{
		Path:       expectedPath,
		Level:      "info",
		FileFormat: LogFileFormatJSON,
		Console:    false,
		MaxSizeMB:  100,
		MaxBackups: 3,
		MaxAgeDays: 28,
	}, meta)

	log := zerowrap.FromCtx(ctx)
	log.Info().Str("test_case", "defaults").Msg("default log event")
	logCleanup.Close()

	entry := readSingleJSONLogEntry(t, meta.Path)
	require.Equal(t, "info", entry["level"])
	require.Equal(t, "default log event", entry["message"])
	require.Equal(t, "defaults", entry["test_case"])
	require.Equal(t, AppName, entry["service"])
	require.Equal(t, "test-version", entry["version"])

	stderrBytes, err := os.ReadFile(stderrPath)
	require.NoError(t, err)
	require.Empty(t, string(stderrBytes))
}

func TestNewContextFromEnvExplicitPathCreatesParentDirectories(t *testing.T) {
	explicitPath := filepath.Join(t.TempDir(), "nested", "deeper", "app.log")
	t.Setenv(envLogPath, explicitPath)

	ctx, cleanup, meta, err := NewContextFromEnv(context.Background(), "")
	require.NoError(t, err)
	logCleanup := newSafeCleanup(cleanup)
	defer logCleanup.Close()
	require.Equal(t, explicitPath, meta.Path)
	require.DirExists(t, filepath.Dir(explicitPath))

	log := zerowrap.FromCtx(ctx)
	log.Info().Msg("explicit path event")
	logCleanup.Close()

	data, err := os.ReadFile(explicitPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "explicit path event")
}

func TestNewContextFromEnvConsoleMirrorWritesToStderr(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv(envLogConsole, "true")
	stderrPath, restoreStderr := captureStderrToTempFile(t)
	defer restoreStderr()

	ctx, cleanup, meta, err := NewContextFromEnv(context.Background(), "")
	require.NoError(t, err)
	logCleanup := newSafeCleanup(cleanup)
	defer logCleanup.Close()
	require.True(t, meta.Console)

	log := zerowrap.FromCtx(ctx)
	log.Info().Str("test_case", "console_mirror").Msg("console mirror event")
	logCleanup.Close()

	stderrBytes, err := os.ReadFile(stderrPath)
	require.NoError(t, err)
	require.Contains(t, string(stderrBytes), "console mirror event")

	fileBytes, err := os.ReadFile(meta.Path)
	require.NoError(t, err)
	require.Contains(t, string(fileBytes), "console mirror event")
}

func TestNewContextFromEnvRejectsInvalidLevel(t *testing.T) {
	t.Setenv(envLogLevel, "verbose")

	_, _, _, err := NewContextFromEnv(context.Background(), "")

	require.Error(t, err)
	require.Contains(t, err.Error(), envLogLevel)
}

func TestNewContextFromEnvRejectsInvalidFileFormat(t *testing.T) {
	t.Setenv(envLogFormat, "text")

	_, _, _, err := NewContextFromEnv(context.Background(), "")

	require.Error(t, err)
	require.Contains(t, err.Error(), envLogFormat)
}

func TestNewContextFromEnvRejectsInvalidConsoleBool(t *testing.T) {
	t.Setenv(envLogConsole, "sometimes")

	_, _, _, err := NewContextFromEnv(context.Background(), "")

	require.Error(t, err)
	require.Contains(t, err.Error(), envLogConsole)
}

func TestNewContextFromEnvRejectsInvalidRotationValues(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
	}{
		{name: "max size zero", env: envLogMaxSizeMB, value: "0"},
		{name: "max size negative", env: envLogMaxSizeMB, value: "-1"},
		{name: "max size non integer", env: envLogMaxSizeMB, value: "abc"},
		{name: "max backups zero", env: envLogMaxBackups, value: "0"},
		{name: "max backups negative", env: envLogMaxBackups, value: "-1"},
		{name: "max backups non integer", env: envLogMaxBackups, value: "abc"},
		{name: "max age zero", env: envLogMaxAgeDays, value: "0"},
		{name: "max age negative", env: envLogMaxAgeDays, value: "-1"},
		{name: "max age non integer", env: envLogMaxAgeDays, value: "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.env, tt.value)

			_, _, _, err := NewContextFromEnv(context.Background(), "")

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.env)
		})
	}
}

func TestNewContextFromEnvAcceptsConsoleFileFormat(t *testing.T) {
	explicitPath := filepath.Join(t.TempDir(), "logs", "console.log")
	t.Setenv(envLogPath, explicitPath)
	t.Setenv(envLogFormat, string(LogFileFormatConsole))

	ctx, cleanup, meta, err := NewContextFromEnv(context.Background(), "")
	require.NoError(t, err)
	logCleanup := newSafeCleanup(cleanup)
	defer logCleanup.Close()
	require.Equal(t, LogFileFormatConsole, meta.FileFormat)

	log := zerowrap.FromCtx(ctx)
	log.Info().Msg("console file format event")
	logCleanup.Close()

	data, err := os.ReadFile(explicitPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "console file format event")
	require.NotContains(t, strings.TrimSpace(string(data)), `{"level"`)
}

func captureStderrToTempFile(t *testing.T) (string, func()) {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "stderr-*.log")
	require.NoError(t, err)

	original := os.Stderr
	os.Stderr = file

	return file.Name(), func() {
		_ = file.Sync()
		os.Stderr = original
		_ = file.Close()
	}
}

func readSingleJSONLogEntry(t *testing.T, path string) map[string]any {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1, "expected one log line in %s", path)

	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
	return entry
}
