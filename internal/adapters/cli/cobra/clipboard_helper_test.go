package cobra

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard"
	"github.com/stretchr/testify/require"
)

func TestClipboardHelperCommandIsHidden(t *testing.T) {
	cmd := newClipboardHelperCmd(Options{})

	require.True(t, cmd.Hidden)
	require.Equal(t, clipboard.HelperCommandName, cmd.Use)
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
	cmd.SetArgs([]string{clipboard.HelperCommandName, "--ttl", "2s"})
	cmd.SetIn(strings.NewReader("secret-password"))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()

	require.NoError(t, err)
	require.Equal(t, []byte("secret-password"), got)
	require.Equal(t, 2*time.Second, gotTTL)
}
