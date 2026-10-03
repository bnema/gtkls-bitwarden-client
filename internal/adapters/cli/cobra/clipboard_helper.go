package cobra

import (
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard"
	"github.com/spf13/cobra"
)

// newClipboardHelperCmd registers the hidden subcommand re-executed by the
// clipboard module. Argv/stdin parsing lives in the clipboard package; flags
// are disabled here so it owns the whole protocol.
func newClipboardHelperCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:                clipboard.HelperCommandName,
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return clipboard.RunHelper(cmd.Context(), args, cmd.InOrStdin(), opts.ClipboardHelperProvider)
		},
	}
}
