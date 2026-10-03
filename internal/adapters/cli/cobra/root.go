package cobra

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bnema/zerowrap"
	"github.com/spf13/cobra"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/compose"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/gtk"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/layershell"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/paths/xdg"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	safelog "github.com/bnema/gtkls-bitwarden-client/internal/core/logging"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
)

// Options holds configuration for the CLI.
type Options struct {
	Version    string
	ConfigPath string
	// RunOverlay runs the application overlay. If nil, the default GTK overlay
	// is created and started. Injecting a test double keeps tests headless.
	RunOverlay func(context.Context, in.AppService) error
	// ComposeService builds the application service. If nil, production adapters
	// are used. Injecting a test double keeps auth command tests offline.
	ComposeService func(context.Context, *coreconfig.Config, string, string) (in.AppService, error)
	// ClipboardHelperProvider owns clipboard bytes for the hidden internal helper.
	// If nil, the clipboard module's Wayland foreground provider is used. Tests inject this to avoid
	// touching the real desktop clipboard. Secrets must be provided as bytes,
	// never argv/env strings.
	ClipboardHelperProvider clipboard.HelperProvider
}

// NewRootCommand creates the root CLI command with all subcommands.
func NewRootCommand(opts Options) *cobra.Command {
	root := &cobra.Command{
		Use:   "gtkls-bitwarden-client",
		Short: "Bitwarden desktop client for GTK4 layershell",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := zerowrap.FromCtx(cmd.Context()).WithField(zerowrap.FieldComponent, "cli.root")
			log.Info().Str(zerowrap.FieldOperation, "root").Msg("root command started")

			layershell.EnsurePreloaded()
			cmd.Println(fmt.Sprintf("gtkls-bitwarden-client %s", opts.Version))

			// Load config; tolerate missing email for first-run scenarios.
			mgr := newConfigManager(opts)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return fmt.Errorf("config load: %w", err)
			}
			log.Info().Str(zerowrap.FieldOperation, "load_config").Msg("config loaded")

			// Compute cache/outbox paths once.
			cachePath, outboxPath := xdg.Default().CacheFile(), xdg.Default().OutboxFile()

			// Compose application service.
			log.Info().Str(zerowrap.FieldOperation, "compose_service").Msg("service composition started")
			svc, err := composeAppService(opts, cmd.Context(), cfg, cachePath, outboxPath)
			if err != nil {
				return fmt.Errorf("compose service: %w", err)
			}
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(cmd.Context()), 30*time.Second)
				defer cancel()
				if shutdownErr := svc.Shutdown(shutdownCtx); shutdownErr != nil {
					log.Error().
						Str(zerowrap.FieldOperation, "shutdown").
						Str("error_kind", safelog.SafeErrorKind(shutdownErr)).
						Msg("service shutdown failed")
				}
			}()
			log.Info().Str(zerowrap.FieldOperation, "compose_service").Msg("service composition finished")

			// Start config hot-reload watcher using the command's context so that
			// cancellation propagates to the UpdateConfig call.
			go func() {
				watchLog := zerowrap.FromCtx(cmd.Context()).WithField(zerowrap.FieldComponent, "cli.root")
				_ = mgr.Watch(cmd.Context(), func(newCfg *coreconfig.Config) {
					if uerr := svc.UpdateConfig(cmd.Context(), newCfg); uerr != nil {
						watchLog.Warn().
							Str(zerowrap.FieldOperation, "config_hot_reload").
							Str("error_kind", safelog.SafeErrorKind(uerr)).
							Msg("config hot reload rejected")
					}
				})
			}()

			// Run the overlay (default or injected).
			runner := opts.RunOverlay
			if runner == nil {
				runner = func(ctx context.Context, svc in.AppService) error {
					overlay := gtk.NewOverlay(svc, gtk.Options{Version: opts.Version})
					return overlay.Run(ctx)
				}
			}

			log.Info().Str(zerowrap.FieldOperation, "run_overlay").Msg("overlay started")
			if err := runner(cmd.Context(), svc); err != nil {
				if strings.Contains(err.Error(), "layer-shell is not available") {
					return fmt.Errorf("%w\n\nGTK layer-shell is not available in this session. Use `gtkls-bitwarden-client login`, `unlock`, or `status` from a terminal, or run the overlay inside a layer-shell-capable Wayland compositor", err)
				}
				return err
			}
			log.Info().Str(zerowrap.FieldOperation, "run_overlay").Msg("overlay finished")
			return nil
		},
	}

	// Derive default cache/outbox paths once for subcommands.
	cachePath, outboxPath := xdg.Default().CacheFile(), xdg.Default().OutboxFile()

	root.AddCommand(newConfigCmd(opts))
	root.AddCommand(newLoginCmd(opts, cachePath, outboxPath))
	root.AddCommand(newUnlockCmd(opts, cachePath, outboxPath))
	root.AddCommand(newStatusCmd(opts, cachePath, outboxPath))
	root.AddCommand(newLockCmd(opts, cachePath, outboxPath))
	root.AddCommand(newCacheCmd(cachePath, outboxPath))
	root.AddCommand(newLogoutCmd(opts, cachePath, outboxPath))
	root.AddCommand(newSyncCmd())
	root.AddCommand(newClipboardHelperCmd(opts))

	return root
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

// composeAppService returns the injected service when Options.ComposeService is
// set, otherwise the production service built by the compose package.
// cachePath and outboxPath should be computed once by the caller.
func composeAppService(opts Options, ctx context.Context, cfg *coreconfig.Config, cachePath, outboxPath string) (in.AppService, error) {
	if opts.ComposeService != nil {
		return opts.ComposeService(ctx, cfg, cachePath, outboxPath)
	}
	return compose.Service(ctx, cfg, cachePath, outboxPath)
}

// newConfigManager returns the configuration manager for the CLI config path.
func newConfigManager(opts Options) compose.ConfigManager {
	return compose.NewConfigManager(opts.ConfigPath)
}

// ---------------------------------------------------------------------------
// Config subcommand
// ---------------------------------------------------------------------------

// newConfigCmd creates the "config" subcommand and its children.
func newConfigCmd(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print the config file path",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := newConfigManager(opts)
			cmd.Println(mgr.Path())
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := newConfigManager(opts)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return err
			}
			if err := coreconfig.Validate(cfg); err != nil {
				return err
			}
			cmd.Println("ok")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "get <key>",
		Short: "Get a config value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := newConfigManager(opts)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return err
			}
			val, err := getConfigValue(cfg, args[0])
			if err != nil {
				return err
			}
			cmd.Println(val)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a config value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := newConfigManager(opts)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return err
			}
			if err := setConfigValue(cfg, args[0], args[1]); err != nil {
				return err
			}
			return mgr.Save(cmd.Context(), cfg)
		},
	})

	return cmd
}

// ---------------------------------------------------------------------------
// Cache subcommand
// ---------------------------------------------------------------------------

// newCacheCmd creates the "cache" command with a "clear" subcommand.
func newCacheCmd(cachePath, outboxPath string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage cache",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Clear the cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := compose.ClearLocalData(cmd.Context(), cachePath, outboxPath); err != nil {
				return err
			}
			cmd.Println("cache cleared")
			return nil
		},
	})

	return cmd
}

// ---------------------------------------------------------------------------
// Logout subcommand
// ---------------------------------------------------------------------------

// newLogoutCmd removes the token bundle, unlock envelope, encrypted cache,
// and encrypted outbox.
func newLogoutCmd(opts Options, cachePath, outboxPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out of Bitwarden",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := newConfigManager(opts)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return fmt.Errorf("config load: %w", err)
			}

			// Only delete credentials when an email is configured.
			if cfg.Bitwarden.Email != "" {
				if err := forgetAccount(cmd.Context(), opts, cfg, cachePath, outboxPath); err != nil {
					return fmt.Errorf("logout: %w", err)
				}
			}

			if err := compose.ClearLocalData(cmd.Context(), cachePath, outboxPath); err != nil {
				return err
			}

			// Logout returns the local account setup to a first-run state so the
			// next `login` prompts for the account identity again.
			cfg.Bitwarden.Email = ""
			cfg.Bitwarden.ServerURL = ""
			if err := mgr.Save(cmd.Context(), cfg); err != nil {
				return fmt.Errorf("clear account config: %w", err)
			}

			cmd.Println("logged out")
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// Sync subcommand
// ---------------------------------------------------------------------------

// newSyncCmd creates the "sync" subcommand. A --force flag is accepted for
// future use but currently sync runs automatically after unlock.
func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync with Bitwarden",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return err
			}
			if force {
				cmd.Println("force sync requested; sync runs automatically after unlock")
				return nil
			}
			cmd.Println("sync runs automatically after unlock")
			return nil
		},
	}
	cmd.Flags().BoolP("force", "f", false, "Force a full sync")
	return cmd
}

// ---------------------------------------------------------------------------
// Config key helpers (unchanged)
// ---------------------------------------------------------------------------

// supportedGetKeys lists the keys that can be read via "config get".
var supportedGetKeys = map[string]bool{
	"bitwarden.email":                true,
	"bitwarden.region":               true,
	"bitwarden.server_url":           true,
	"appearance.ui_scale":            true,
	"appearance.color_scheme":        true,
	"actions.default_primary_action": true,
	"actions.close_after_copy":       true,
	"sync.revision_check_interval":   true,
	"security.idle_relock_after":     true,
	"security.resident_relock_after": true,
	"cache.ttl":                      true,
}

// supportedSetKeys lists the keys that can be written via "config set".
var supportedSetKeys = map[string]bool{
	"bitwarden.email":                true,
	"bitwarden.region":               true,
	"bitwarden.server_url":           true,
	"appearance.ui_scale":            true,
	"appearance.color_scheme":        true,
	"actions.default_primary_action": true,
	"actions.close_after_copy":       true,
}

// getConfigValue returns the string representation of a config key.
func getConfigValue(cfg *coreconfig.Config, key string) (string, error) {
	if !supportedGetKeys[key] {
		return "", fmt.Errorf("unsupported config key: %s", key)
	}

	switch key {
	case "bitwarden.email":
		return cfg.Bitwarden.Email, nil
	case "bitwarden.region":
		return string(cfg.Bitwarden.Region), nil
	case "bitwarden.server_url":
		return cfg.Bitwarden.ServerURL, nil
	case "appearance.ui_scale":
		return strconv.FormatFloat(cfg.Appearance.UIScale, 'f', -1, 64), nil
	case "appearance.color_scheme":
		return string(cfg.Appearance.ColorScheme), nil
	case "actions.default_primary_action":
		return string(cfg.Actions.DefaultPrimaryAction), nil
	case "actions.close_after_copy":
		return strconv.FormatBool(cfg.Actions.CloseAfterCopy), nil
	case "sync.revision_check_interval":
		return cfg.Sync.RevisionCheckInterval.String(), nil
	case "security.idle_relock_after":
		return cfg.Security.IdleRelockAfter.String(), nil
	case "security.resident_relock_after":
		return cfg.Security.ResidentRelockAfter.String(), nil
	case "cache.ttl":
		return cfg.Cache.TTL.String(), nil
	default:
		return "", fmt.Errorf("unsupported config key: %s", key)
	}
}

// setConfigValue sets a config key from its string representation.
func setConfigValue(cfg *coreconfig.Config, key, value string) error {
	if !supportedSetKeys[key] {
		return fmt.Errorf("unsupported config key: %s", key)
	}

	switch key {
	case "bitwarden.email":
		cfg.Bitwarden.Email = value
	case "bitwarden.region":
		cfg.Bitwarden.Region = coreconfig.Region(value)
	case "bitwarden.server_url":
		cfg.Bitwarden.ServerURL = value
	case "appearance.ui_scale":
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("invalid float value for %s: %w", key, err)
		}
		cfg.Appearance.UIScale = f
	case "appearance.color_scheme":
		cfg.Appearance.ColorScheme = coreconfig.ColorScheme(value)
	case "actions.default_primary_action":
		cfg.Actions.DefaultPrimaryAction = coreconfig.PrimaryAction(value)
	case "actions.close_after_copy":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid bool value for %s: %w", key, err)
		}
		cfg.Actions.CloseAfterCopy = b
	default:
		return fmt.Errorf("unsupported config key: %s", key)
	}

	return nil
}
