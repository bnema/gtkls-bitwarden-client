package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	adapterlogging "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/logging"
)

func TestRunInitializesFileOnlyLogging(t *testing.T) {
	stateHome := t.TempDir()
	setCleanRuntimeEnv(t, stateHome)

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"status"}, &stdout, &stderr)
	require.Equal(t, 0, exitCode)

	stdoutText := stdout.String()
	stderrText := stderr.String()
	require.NotContains(t, stdoutText, "logging initialized")
	require.NotContains(t, stderrText, "logging initialized")
	require.NotContains(t, stdoutText, "log_level")
	require.NotContains(t, stderrText, "log_level")
	require.Empty(t, stderrText)

	logPath := filepath.Join(stateHome, adapterlogging.AppName, "logs", adapterlogging.AppName+".log")
	entries := readJSONLogEntries(t, logPath)
	require.NotEmpty(t, entries)

	entry := entries[0]
	require.Equal(t, "logging initialized", entry["message"])
	require.Equal(t, logPath, entry["log_path"])
	require.Equal(t, "info", entry["log_level"])
	require.Equal(t, "json", entry["file_format"])
	require.Equal(t, false, entry["console"])
}

func TestRunReportsLoggerInitializationError(t *testing.T) {
	setCleanRuntimeEnv(t, t.TempDir())
	t.Setenv("GLSBW_LOG_LEVEL", "verbose")

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"status"}, &stdout, &stderr)

	require.Equal(t, 1, exitCode)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), "error: initialize logging:")
	require.Contains(t, stderr.String(), "GLSBW_LOG_LEVEL")
}

func TestRunLogsCommandFailureWithSafeErrorKind(t *testing.T) {
	stateHome := t.TempDir()
	setCleanRuntimeEnv(t, stateHome)

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"config", "validate"}, &stdout, &stderr)

	require.Equal(t, 1, exitCode)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), "error: config: email is required")

	logPath := filepath.Join(stateHome, adapterlogging.AppName, "logs", adapterlogging.AppName+".log")
	entries := readJSONLogEntries(t, logPath)
	require.Len(t, entries, 2)
	require.Equal(t, "command failed", entries[1]["message"])
	require.Equal(t, "error", entries[1]["error_kind"])
	require.NotContains(t, string(mustReadFile(t, logPath)), "email is required")
}

func setCleanRuntimeEnv(t *testing.T, stateHome string) {
	t.Helper()
	runtimeDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(runtimeDir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(runtimeDir, "cache"))
	t.Setenv("GLSBW_LOG_LEVEL", "")
	t.Setenv("GLSBW_LOG_FORMAT", "")
	t.Setenv("GLSBW_LOG_CONSOLE", "")
	t.Setenv("GLSBW_LOG_PATH", "")
	t.Setenv("GLSBW_LOG_MAX_SIZE_MB", "")
	t.Setenv("GLSBW_LOG_MAX_BACKUPS", "")
	t.Setenv("GLSBW_LOG_MAX_AGE_DAYS", "")
}

func readJSONLogEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	data := mustReadFile(t, path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	entries := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		entries = append(entries, entry)
	}
	return entries
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
