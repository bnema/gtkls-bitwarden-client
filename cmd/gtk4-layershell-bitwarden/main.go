package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/bnema/zerowrap"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/cli/cobra"
	adapterlogging "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/logging"
	corelogging "github.com/bnema/gtk4-layershell-bitwarden/internal/core/logging"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	ctx, cleanup, meta, err := adapterlogging.NewContextFromEnv(context.Background(), version)
	if err != nil {
		fmt.Fprintf(stderr, "error: initialize logging: %v\n", err)
		return 1
	}
	defer cleanup()

	log := zerowrap.FromCtx(ctx)
	log.Info().
		Str("log_path", meta.Path).
		Str("log_level", meta.Level).
		Str("file_format", string(meta.FileFormat)).
		Bool("console", meta.Console).
		Msg("logging initialized")

	root := cobra.NewRootCommand(cobra.Options{Version: version})
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SilenceErrors = true
	root.SilenceUsage = true

	if err := root.ExecuteContext(ctx); err != nil {
		log.Error().
			Str("error_kind", corelogging.SafeErrorKind(err)).
			Msg("command failed")
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}
