package cobra

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	viperadapter "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/config/viper"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
)

// Options holds configuration for the CLI.
type Options struct {
	Version    string
	ConfigPath string
}

// NewRootCommand creates the root CLI command with all subcommands.
func NewRootCommand(opts Options) *cobra.Command {
	root := &cobra.Command{
		Use:   "gtk4-layershell-bitwarden",
		Short: "Bitwarden desktop client for GTK4 layershell",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println(fmt.Sprintf("gtk4-layershell-bitwarden %s", opts.Version))
			// Load config to verify it can be read; tolerate missing email
			// for first-run scenarios.
			mgr := viperadapter.NewManager(opts.ConfigPath)
			_, err := mgr.Load(cmd.Context())
			if err != nil {
				return fmt.Errorf("config load: %w", err)
			}
			return nil
		},
	}

	root.AddCommand(newConfigCmd(opts))
	root.AddCommand(newCacheCmd())
	root.AddCommand(newLogoutCmd())
	root.AddCommand(newSyncCmd())

	return root
}

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

// newCacheCmd creates the "cache" command with a "clear" subcommand.
func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage cache",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Clear the cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("cache clear not wired yet")
			return nil
		},
	})

	return cmd
}

// newLogoutCmd creates the "logout" subcommand.
func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out of Bitwarden",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("logout not wired yet")
			return nil
		},
	}
}

// newSyncCmd creates the "sync" subcommand with a --force flag.
func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync with Bitwarden",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("sync not wired yet")
			return nil
		},
	}
	cmd.Flags().BoolP("force", "f", false, "Force a full sync")
	return cmd
}

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
