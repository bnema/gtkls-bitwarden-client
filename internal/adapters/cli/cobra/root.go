package cobra

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bnema/zerowrap"
	"github.com/spf13/cobra"

	cryptobox "github.com/bnema/gtkls-bitwarden-client/internal/adapters/cache/crypto"
	cachefile "github.com/bnema/gtkls-bitwarden-client/internal/adapters/cache/file"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/gtk"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/layershell"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/paths/xdg"
	remoteadapter "github.com/bnema/gtkls-bitwarden-client/internal/adapters/remote/bitwarden"
	keyring "github.com/bnema/gtkls-bitwarden-client/internal/adapters/secrets/keyring"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/session/bootid"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/session/pinenvelope"
	"github.com/bnema/gtkls-bitwarden-client/internal/app"
	viperadapter "github.com/bnema/gtkls-bitwarden-client/internal/app/viper"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	safelog "github.com/bnema/gtkls-bitwarden-client/internal/core/logging"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/session"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
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
	// CredentialStore backs lock/logout keyring operations. If nil, keyring.New()
	// is used. Injecting a test double prevents tests from touching the real
	// OS secret service.
	CredentialStore out.CredentialStore
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
			mgr := viperadapter.NewManager(opts.ConfigPath)
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
	root.AddCommand(newLockCmd(opts))
	root.AddCommand(newCacheCmd(cachePath, outboxPath))
	root.AddCommand(newLogoutCmd(opts, cachePath, outboxPath))
	root.AddCommand(newSyncCmd())

	return root
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

// composeService builds all application dependencies and returns the service.
// cachePath and outboxPath should be computed once by the caller.
func composeAppService(opts Options, ctx context.Context, cfg *coreconfig.Config, cachePath, outboxPath string) (in.AppService, error) {
	if opts.ComposeService != nil {
		return opts.ComposeService(ctx, cfg, cachePath, outboxPath)
	}
	return composeService(ctx, cfg, cachePath, outboxPath)
}

func composeService(ctx context.Context, cfg *coreconfig.Config, cachePath, outboxPath string) (in.AppService, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Secret box for cache/outbox encryption.
	box := cryptobox.NewBox()

	// File-backed cache and outbox stores.
	cacheStore := cachefile.NewStore(cachePath)
	outboxStore := cachefile.NewOutboxStore(outboxPath, box)

	// Bitwarden remote adapter.
	remote, err := remoteadapter.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("remote client: %w", err)
	}

	// Session infrastructure: OS keyring, boot ID, PIN envelope.
	credentials := keyring.New()
	bootID := bootid.New()
	pinEnvelope := pinenvelope.New(pinenvelope.ServiceConfig{})

	// Application service.
	svc := app.NewService(app.Deps{
		Remote:      remote,
		Cache:       cacheStore,
		Outbox:      outboxStore,
		SecretBox:   box,
		Config:      cfg,
		Credentials: credentials,
		BootID:      bootID,
		PINEnvelope: pinEnvelope,
		// Clock can be nil; service falls back to time.Now.
	})

	return svc, nil
}

// ---------------------------------------------------------------------------
// Credential helpers for lock/logout
// ---------------------------------------------------------------------------

var (
	defaultCredentialStoreOnce sync.Once
	defaultCredentialStore     out.CredentialStore
)

// credentialStore returns the CredentialStore to use for lock/logout operations.
func credentialStore(opts Options) out.CredentialStore {
	if opts.CredentialStore != nil {
		return opts.CredentialStore
	}
	defaultCredentialStoreOnce.Do(func() {
		defaultCredentialStore = keyring.New()
	})
	return defaultCredentialStore
}

// accountRefFromConfig builds an AccountRef from the config's email and
// effective server URL.
func accountRefFromConfig(cfg *coreconfig.Config) session.AccountRef {
	return session.AccountRef{
		Email:     cfg.Bitwarden.Email,
		ServerURL: effectiveServerURL(cfg),
	}
}

// deleteUnlockEnvelopeForConfig checks keyring availability and deletes the
// unlock envelope for the configured account. Token bundle and cache are
// left untouched.
func deleteUnlockEnvelopeForConfig(ctx context.Context, store out.CredentialStore, cfg *coreconfig.Config) error {
	if err := store.CheckAvailable(ctx); err != nil {
		return fmt.Errorf("check credential store: %w", err)
	}
	ref := accountRefFromConfig(cfg)
	if err := store.DeleteUnlockEnvelope(ctx, ref); err != nil {
		return fmt.Errorf("delete unlock envelope: %w", err)
	}
	return nil
}

// deleteCredentialsForConfig checks keyring availability and deletes the
// unlock envelope, token bundle, and PIN profile for the configured account.
func deleteCredentialsForConfig(ctx context.Context, store out.CredentialStore, cfg *coreconfig.Config) error {
	if err := store.CheckAvailable(ctx); err != nil {
		return fmt.Errorf("check credential store: %w", err)
	}
	ref := accountRefFromConfig(cfg)
	if err := store.DeleteUnlockEnvelope(ctx, ref); err != nil {
		return fmt.Errorf("delete unlock envelope: %w", err)
	}
	if err := store.DeleteTokenBundle(ctx, ref); err != nil {
		return fmt.Errorf("delete token bundle: %w", err)
	}
	if err := store.DeletePINProfile(ctx, ref); err != nil {
		return fmt.Errorf("delete pin profile: %w", err)
	}
	return nil
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
			mgr := viperadapter.NewManager(opts.ConfigPath)
			cmd.Println(mgr.Path())
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := viperadapter.NewManager(opts.ConfigPath)
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
			mgr := viperadapter.NewManager(opts.ConfigPath)
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
			mgr := viperadapter.NewManager(opts.ConfigPath)
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

// clearCacheAndOutbox clears both the cache and outbox stores, returning an
// error if either operation fails.
func clearCacheAndOutbox(ctx context.Context, cachePath, outboxPath string) error {
	box := cryptobox.NewBox()
	cacheStore := cachefile.NewStore(cachePath)
	outboxStore := cachefile.NewOutboxStore(outboxPath, box)

	if err := cacheStore.Clear(ctx); err != nil {
		return fmt.Errorf("cache clear: %w", err)
	}
	if err := outboxStore.Clear(ctx); err != nil {
		return fmt.Errorf("outbox clear: %w", err)
	}
	return nil
}

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
			if err := clearCacheAndOutbox(cmd.Context(), cachePath, outboxPath); err != nil {
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
			mgr := viperadapter.NewManager(opts.ConfigPath)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return fmt.Errorf("config load: %w", err)
			}

			// Only delete credentials when an email is configured.
			if cfg.Bitwarden.Email != "" {
				store := credentialStore(opts)
				if err := deleteCredentialsForConfig(cmd.Context(), store, cfg); err != nil {
					return fmt.Errorf("logout: %w", err)
				}
			}

			if err := clearCacheAndOutbox(cmd.Context(), cachePath, outboxPath); err != nil {
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
