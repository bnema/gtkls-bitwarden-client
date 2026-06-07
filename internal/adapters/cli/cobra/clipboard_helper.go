package cobra

import (
	"context"
	"fmt"
	"io"
	"time"

	clipadapter "github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard/helpercmd"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/secretmem"
	"github.com/spf13/cobra"
)

const maxClipboardSecretBytes = 64 * 1024

func newClipboardHelperCmd(opts Options) *cobra.Command {
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:    helpercmd.CommandName,
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClipboardHelper(cmd.Context(), opts, cmd.InOrStdin(), ttl)
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "clipboard lifetime before helper exits")
	return cmd
}

func runClipboardHelper(ctx context.Context, opts Options, stdin io.Reader, ttl time.Duration) error {
	if ttl < 0 {
		return fmt.Errorf("clipboard helper: ttl must be non-negative")
	}
	var writeErr error
	secretmem.Do(func() {
		var text []byte
		text, writeErr = readClipboardHelperStdin(stdin)
		if writeErr != nil {
			writeErr = fmt.Errorf("clipboard helper: read stdin: %w", writeErr)
			return
		}
		defer zeroBytes(text)

		provider := opts.ClipboardHelperProvider
		if provider == nil {
			provider = clipadapter.NewWaylandForegroundProvider().Serve
		}
		writeErr = provider(ctx, text, ttl)
	})
	if writeErr != nil {
		return writeErr
	}
	return nil
}

func readClipboardHelperStdin(stdin io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, maxClipboardSecretBytes+1))
	if err != nil {
		zeroBytes(data)
		return nil, err
	}
	if len(data) > maxClipboardSecretBytes {
		zeroBytes(data)
		return nil, fmt.Errorf("clipboard helper: stdin exceeds %d bytes", maxClipboardSecretBytes)
	}
	return data, nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
