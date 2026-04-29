package cobra

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	viperadapter "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/config/viper"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

type authOptions struct {
	raw          bool
	passwordEnv  string
	passwordFile string
	noSync       bool
}

type statusResponse struct {
	ServerURL string `json:"serverUrl,omitempty"`
	LastSync  string `json:"lastSync,omitempty"`
	UserEmail string `json:"userEmail,omitempty"`
	Status    string `json:"status"`
}

func newLoginCmd(opts Options, cachePath, outboxPath string) *cobra.Command {
	var auth authOptions
	cmd := &cobra.Command{
		Use:   "login [email] [password]",
		Short: "Log in to Bitwarden",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLoginUnlock(cmd, opts, cachePath, outboxPath, args, auth, true)
		},
	}
	addAuthFlags(cmd, &auth)
	return cmd
}

func newUnlockCmd(opts Options, cachePath, outboxPath string) *cobra.Command {
	var auth authOptions
	cmd := &cobra.Command{
		Use:   "unlock [password]",
		Short: "Unlock the local vault cache",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLoginUnlock(cmd, opts, cachePath, outboxPath, args, auth, false)
		},
	}
	addAuthFlags(cmd, &auth)
	return cmd
}

func addAuthFlags(cmd *cobra.Command, auth *authOptions) {
	cmd.Flags().BoolVar(&auth.raw, "raw", false, "Return only the session key")
	cmd.Flags().StringVar(&auth.passwordEnv, "passwordenv", "", "Environment variable containing the master password")
	cmd.Flags().StringVar(&auth.passwordFile, "passwordfile", "", "File containing the master password")
	cmd.Flags().BoolVar(&auth.noSync, "no-sync", false, "Unlock then exit without waiting for background sync")
}

func runLoginUnlock(cmd *cobra.Command, opts Options, cachePath, outboxPath string, args []string, auth authOptions, login bool) error {
	mgr := viperadapter.NewManager(opts.ConfigPath)
	cfg, err := mgr.Load(cmd.Context())
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	email := cfg.Bitwarden.Email
	passwordArgs := args
	if login {
		if len(args) > 0 {
			email = args[0]
		}
		if strings.TrimSpace(email) == "" {
			prompted, err := promptLine(cmd.InOrStdin(), cmd.ErrOrStderr(), "Email address: ")
			if err != nil {
				return err
			}
			email = strings.TrimSpace(prompted)
		}
		passwordArgs = nil
		if len(args) > 1 {
			passwordArgs = []string{args[1]}
		}
	} else if strings.TrimSpace(email) == "" {
		return fmt.Errorf("no configured email; run `gtk4-layershell-bitwarden login <email>` first or set bitwarden.email")
	}

	password, err := resolvePassword(cmd, passwordArgs, auth)
	if err != nil {
		return err
	}

	if login && cfg.Bitwarden.Email != email {
		cfg.Bitwarden.Email = email
		if err := mgr.Save(cmd.Context(), cfg); err != nil {
			return fmt.Errorf("save email: %w", err)
		}
	}

	svc, err := composeAppService(opts, cmd.Context(), cfg, cachePath, outboxPath)
	if err != nil {
		return fmt.Errorf("compose service: %w", err)
	}
	defer func() { _ = svc.Shutdown(context.Background()) }()

	if err := svc.Unlock(cmd.Context(), email, password); err != nil {
		return err
	}
	if !auth.noSync {
		waitForInitialSync(cmd.Context(), svc.Events(), 30*time.Second)
	}

	session, err := newSessionKey()
	if err != nil {
		return err
	}
	_ = os.Setenv("BW_SESSION", session)
	if auth.raw {
		cmd.Println(session)
		return nil
	}

	if login {
		cmd.Println("You are logged in!")
	} else {
		cmd.Println("Your vault is now unlocked!")
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nTo unlock your vault in this shell, set the session key to the `BW_SESSION` environment variable. ex:\n")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "$ export BW_SESSION=%q\n", session)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "> $env:BW_SESSION=%q\n", session)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nYou can also pass the session key to compatible commands with `--session` in future releases.\n")
	return nil
}

func resolvePassword(cmd *cobra.Command, args []string, auth authOptions) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	if auth.passwordEnv != "" {
		value := os.Getenv(auth.passwordEnv)
		if value == "" {
			return "", fmt.Errorf("password environment variable %s is empty", auth.passwordEnv)
		}
		return strings.TrimRight(value, "\r\n"), nil
	}
	if auth.passwordFile != "" {
		data, err := os.ReadFile(auth.passwordFile)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}

	return promptPassword(cmd.InOrStdin(), cmd.ErrOrStderr())
}

func promptLine(in io.Reader, errOut io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(errOut, prompt)
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptPassword(in io.Reader, errOut io.Writer) (string, error) {
	_, _ = fmt.Fprint(errOut, "Master password: ")
	if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		password, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(errOut)
		if err != nil {
			return "", err
		}
		return string(password), nil
	}
	return promptLine(in, errOut, "")
}

func newSessionKey() (string, error) {
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func waitForInitialSync(ctx context.Context, events <-chan in.Event, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			switch event.Kind {
			case in.SyncUpdated, in.SyncFailed:
				return
			}
		}
	}
}

func newStatusCmd(opts Options, cachePath string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := viperadapter.NewManager(opts.ConfigPath)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return err
			}
			status := statusResponse{
				ServerURL: effectiveServerURL(cfg),
				UserEmail: cfg.Bitwarden.Email,
				Status:    "unauthenticated",
			}
			if cfg.Bitwarden.Email != "" {
				status.Status = "locked"
			}
			if info, err := os.Stat(cachePath); err == nil {
				status.LastSync = info.ModTime().UTC().Format(time.RFC3339)
			}
			data, err := json.MarshalIndent(status, "", "  ")
			if err != nil {
				return err
			}
			cmd.Println(string(data))
			return nil
		},
	}
}

func effectiveServerURL(cfg *coreconfig.Config) string {
	if cfg.Bitwarden.Region == coreconfig.RegionSelfHosted {
		return cfg.Bitwarden.ServerURL
	}
	if cfg.Bitwarden.Region == coreconfig.RegionEU {
		return "https://vault.bitwarden.eu"
	}
	return "https://vault.bitwarden.com"
}

// newLockCmd mirrors `bw lock` for this short-lived CLI process: it clears
// BW_SESSION in the current process only. Persistent vault data is protected by
// the encrypted cache and is cleared with `logout` / `cache clear`.
func newLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the current CLI process session (clears BW_SESSION only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = os.Unsetenv("BW_SESSION")
			cmd.Println("Your vault is locked.")
			return nil
		},
	}
}
