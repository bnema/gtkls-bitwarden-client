package clipboard

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard/helpercmd"
	"github.com/stretchr/testify/require"
)

type fakeHelperRunner struct {
	cmd   helperCommand
	stdin []byte
}

func (r *fakeHelperRunner) Run(_ context.Context, cmd helperCommand, stdin io.Reader) error {
	r.cmd = cmd
	data, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	r.stdin = append([]byte(nil), data...)
	return nil
}

func TestHelperClipboardSetPassesSecretOnStdinOnly(t *testing.T) {
	runner := &fakeHelperRunner{}
	clip := &HelperClipboard{
		executable: func() (string, error) { return "/bin/gtkls-bitwarden-client", nil },
		runner:     runner,
	}

	err := clip.Set(context.Background(), "secret-password", 45*time.Second)

	require.NoError(t, err)
	require.Equal(t, "/bin/gtkls-bitwarden-client", runner.cmd.name)
	require.Equal(t, []string{helpercmd.CommandName, "--ttl", "45s"}, runner.cmd.args)
	require.Equal(t, []byte("secret-password"), runner.stdin)
	for _, arg := range runner.cmd.args {
		require.NotContains(t, arg, "secret-password")
	}
}

func TestHelperClipboardSetRejectsNegativeTTL(t *testing.T) {
	clip := &HelperClipboard{}

	err := clip.Set(context.Background(), "secret", -time.Second)

	require.Error(t, err)
	require.Contains(t, err.Error(), "ttl must be non-negative")
}

func TestProcessHelperRunnerReportsStartupFailure(t *testing.T) {
	binDir := t.TempDir()
	helperPath := filepath.Join(binDir, "helper")
	script := "#!/bin/sh\ncat >/dev/null\nexit 42\n"
	require.NoError(t, os.WriteFile(helperPath, []byte(script), 0o700))

	err := processHelperRunner{}.Run(context.Background(), helperCommand{name: helperPath}, strings.NewReader("secret"))

	require.Error(t, err)
	require.Contains(t, err.Error(), "exited during startup")
}

func TestProcessHelperRunnerReleasesLongRunningHelperAfterStartup(t *testing.T) {
	binDir := t.TempDir()
	outPath := filepath.Join(t.TempDir(), "stdin.txt")
	helperPath := filepath.Join(binDir, "helper")
	script := "#!/bin/sh\ncat > \"$HELPER_TEST_OUT\"\nsleep 1\n"
	require.NoError(t, os.WriteFile(helperPath, []byte(script), 0o700))
	t.Setenv("HELPER_TEST_OUT", outPath)

	started := time.Now()
	err := processHelperRunner{}.Run(context.Background(), helperCommand{name: helperPath}, strings.NewReader("secret"))

	require.NoError(t, err)
	require.Less(t, time.Since(started), time.Second)
	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}

func TestProcessHelperRunnerIgnoresCancellationAfterSecretHandoff(t *testing.T) {
	binDir := t.TempDir()
	outPath := filepath.Join(t.TempDir(), "stdin.txt")
	helperPath := filepath.Join(binDir, "helper")
	script := "#!/bin/sh\ncat > \"$HELPER_TEST_OUT\"\nsleep 1\n"
	require.NoError(t, os.WriteFile(helperPath, []byte(script), 0o700))
	t.Setenv("HELPER_TEST_OUT", outPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- processHelperRunner{}.Run(ctx, helperCommand{name: helperPath}, strings.NewReader("secret"))
	}()

	require.Eventually(t, func() bool {
		_, err := os.Stat(outPath)
		return err == nil
	}, time.Second, 10*time.Millisecond)
	cancel()

	require.NoError(t, <-done)
	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}
