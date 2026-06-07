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

func TestSystemWriterSelectCommand(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		tools    map[string]string
		wantName string
		wantArgs []string
		wantOK   bool
	}{
		{
			name:     "wayland prefers detached wl-copy with plain text options",
			env:      map[string]string{"WAYLAND_DISPLAY": "wayland-1"},
			tools:    map[string]string{"wl-copy": "/bin/wl-copy", "xclip": "/bin/xclip"},
			wantName: "/bin/wl-copy",
			wantArgs: []string{"--foreground", "--type", "text/plain"},
			wantOK:   true,
		},
		{
			name:     "wayland falls back to xclip",
			env:      map[string]string{"WAYLAND_DISPLAY": "wayland-1"},
			tools:    map[string]string{"xclip": "/bin/xclip"},
			wantName: "/bin/xclip",
			wantArgs: []string{"-selection", "clipboard"},
			wantOK:   true,
		},
		{
			name:     "x11 uses xsel when xclip unavailable",
			env:      map[string]string{"DISPLAY": ":0"},
			tools:    map[string]string{"xsel": "/bin/xsel"},
			wantName: "/bin/xsel",
			wantArgs: []string{"--clipboard", "--input"},
			wantOK:   true,
		},
		{
			name:   "headless has no command",
			env:    map[string]string{},
			tools:  map[string]string{"wl-copy": "/bin/wl-copy"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := SystemWriter{
				lookPath: func(name string) (string, error) {
					if path, ok := tt.tools[name]; ok {
						return path, nil
					}
					return "", errors.New("not found")
				},
				getenv: func(name string) string { return tt.env[name] },
			}

			got, ok := writer.selectCommand()
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				return
			}
			require.Equal(t, tt.wantName, got.name)
			require.Equal(t, tt.wantArgs, got.args)
		})
	}
}

func TestSystemWriterWriteClipboardRunsCommandWithInput(t *testing.T) {
	binDir := t.TempDir()
	outPath := filepath.Join(t.TempDir(), "clipboard.txt")
	toolPath := filepath.Join(binDir, "wl-copy")
	script := "#!/bin/sh\ncat > \"$CLIPBOARD_TEST_OUT\"\n"
	require.NoError(t, os.WriteFile(toolPath, []byte(script), 0o700))
	t.Setenv("CLIPBOARD_TEST_OUT", outPath)

	writer := SystemWriter{
		lookPath: func(name string) (string, error) {
			if name == "wl-copy" {
				return toolPath, nil
			}
			return "", errors.New("not found")
		},
		getenv: func(name string) string {
			if name == "WAYLAND_DISPLAY" {
				return "wayland-1"
			}
			return ""
		},
	}

	require.NoError(t, writer.WriteClipboard(context.Background(), "secret"))
	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}

func TestSystemWriterWriteClipboardReturnsWhenWlCopyKeepsServing(t *testing.T) {
	binDir := t.TempDir()
	outPath := filepath.Join(t.TempDir(), "clipboard.txt")
	toolPath := filepath.Join(binDir, "wl-copy")
	script := "#!/bin/sh\ncat > \"$CLIPBOARD_TEST_OUT\"\nsleep 1\n"
	require.NoError(t, os.WriteFile(toolPath, []byte(script), 0o700))
	t.Setenv("CLIPBOARD_TEST_OUT", outPath)

	writer := SystemWriter{
		lookPath: func(name string) (string, error) {
			if name == "wl-copy" {
				return toolPath, nil
			}
			return "", errors.New("not found")
		},
		getenv: func(name string) string {
			if name == "WAYLAND_DISPLAY" {
				return "wayland-1"
			}
			return ""
		},
	}

	started := time.Now()
	require.NoError(t, writer.WriteClipboard(context.Background(), "secret"))
	require.Less(t, time.Since(started), 750*time.Millisecond)
	require.Eventually(t, func() bool {
		got, err := os.ReadFile(outPath)
		return err == nil && string(got) == "secret"
	}, time.Second, 10*time.Millisecond)
}
