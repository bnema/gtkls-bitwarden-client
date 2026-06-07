package clipboard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWaylandForegroundProviderServePassesSecretOnStdin(t *testing.T) {
	binDir := t.TempDir()
	outPath := filepath.Join(t.TempDir(), "clipboard.txt")
	toolPath := filepath.Join(binDir, "wl-copy")
	script := "#!/bin/sh\ncat > \"$CLIPBOARD_TEST_OUT\"\n"
	require.NoError(t, os.WriteFile(toolPath, []byte(script), 0o700))
	t.Setenv("CLIPBOARD_TEST_OUT", outPath)

	provider := WaylandForegroundProvider{
		lookPath: func(name string) (string, error) {
			if name == "wl-copy" {
				return toolPath, nil
			}
			return "", errors.New("not found")
		},
	}

	require.NoError(t, provider.Serve(context.Background(), []byte("secret"), 0))
	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}

func TestWaylandForegroundProviderServeTreatsTTLExpiryAsSuccess(t *testing.T) {
	binDir := t.TempDir()
	outPath := filepath.Join(t.TempDir(), "clipboard.txt")
	toolPath := filepath.Join(binDir, "wl-copy")
	script := "#!/bin/sh\ncat > \"$CLIPBOARD_TEST_OUT\"\nsleep 1\n"
	require.NoError(t, os.WriteFile(toolPath, []byte(script), 0o700))
	t.Setenv("CLIPBOARD_TEST_OUT", outPath)

	provider := WaylandForegroundProvider{
		lookPath: func(name string) (string, error) {
			if name == "wl-copy" {
				return toolPath, nil
			}
			return "", errors.New("not found")
		},
	}

	started := time.Now()
	require.NoError(t, provider.Serve(context.Background(), []byte("secret"), 25*time.Millisecond))
	require.Less(t, time.Since(started), 500*time.Millisecond)
	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}

func TestWaylandForegroundProviderServeRejectsNegativeTTL(t *testing.T) {
	provider := WaylandForegroundProvider{}

	err := provider.Serve(context.Background(), []byte("secret"), -time.Second)

	require.Error(t, err)
	require.Contains(t, err.Error(), "ttl must be non-negative")
}
