package cobra

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard/helpercmd"
	"github.com/stretchr/testify/require"
)

func TestClipboardHelperCommandIsHidden(t *testing.T) {
	cmd := newClipboardHelperCmd(Options{})

	require.True(t, cmd.Hidden)
	require.Equal(t, helpercmd.CommandName, cmd.Use)
}

func TestRootCommandExecutesRegisteredClipboardHelper(t *testing.T) {
	var got []byte
	var gotTTL time.Duration
	cmd := NewRootCommand(Options{
		ClipboardHelperProvider: func(_ context.Context, text []byte, ttl time.Duration) error {
			got = append([]byte(nil), text...)
			gotTTL = ttl
			return nil
		},
	})
	cmd.SetArgs([]string{helpercmd.CommandName, "--ttl", "2s"})
	cmd.SetIn(strings.NewReader("secret-password"))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()

	require.NoError(t, err)
	require.Equal(t, []byte("secret-password"), got)
	require.Equal(t, 2*time.Second, gotTTL)
}

func TestRunClipboardHelperReadsSecretFromStdinOnly(t *testing.T) {
	var got []byte
	var gotTTL time.Duration
	opts := Options{
		ClipboardHelperProvider: func(_ context.Context, text []byte, ttl time.Duration) error {
			got = append([]byte(nil), text...)
			gotTTL = ttl
			return nil
		},
	}

	err := runClipboardHelper(context.Background(), opts, strings.NewReader("secret-password"), 3*time.Second)

	require.NoError(t, err)
	require.Equal(t, []byte("secret-password"), got)
	require.Equal(t, 3*time.Second, gotTTL)
}

func TestRunClipboardHelperRejectsNegativeTTL(t *testing.T) {
	err := runClipboardHelper(context.Background(), Options{}, strings.NewReader("secret"), -time.Second)

	require.Error(t, err)
	require.Contains(t, err.Error(), "ttl must be non-negative")
}

func TestReadClipboardHelperStdinRejectsOversizedInput(t *testing.T) {
	input := bytes.Repeat([]byte("x"), maxClipboardSecretBytes+1)

	data, err := readClipboardHelperStdin(bytes.NewReader(input))

	require.Error(t, err)
	require.Nil(t, data)
	require.Contains(t, err.Error(), "stdin exceeds")
}
