package cobra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	viperadapter "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/config/viper"
	coreauth "github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

type authOptions struct {
	raw          bool
	passwordEnv  string
	passwordFile string
	noSync       bool
	region       string
	serverURL    string
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
			return runLogin(cmd, opts, cachePath, outboxPath, args, auth)
		},
	}
	addAuthFlags(cmd, &auth)
	cmd.Flags().StringVar(&auth.region, "region", "", "Bitwarden region: us, eu, or self_hosted")
	cmd.Flags().StringVar(&auth.serverURL, "server-url", "", "Self-hosted Bitwarden server URL (https://...) when --region self_hosted")
	return cmd
}

func newUnlockCmd(opts Options, cachePath, outboxPath string) *cobra.Command {
	var auth authOptions
	cmd := &cobra.Command{
		Use:   "unlock [pin]",
		Short: "Unlock the local vault cache with your PIN",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUnlock(cmd, opts, cachePath, outboxPath, args, auth)
		},
	}
	addAuthFlags(cmd, &auth)
	return cmd
}

func addAuthFlags(cmd *cobra.Command, auth *authOptions) {
	cmd.Flags().BoolVar(&auth.raw, "raw", false, "Print minimal output (no decoration)")
	cmd.Flags().StringVar(&auth.passwordEnv, "passwordenv", "", "Environment variable containing the master password")
	cmd.Flags().StringVar(&auth.passwordFile, "passwordfile", "", "File containing the master password")
	cmd.Flags().BoolVar(&auth.noSync, "no-sync", false, "Unlock then exit without waiting for background sync")
}

func runLogin(cmd *cobra.Command, opts Options, cachePath, outboxPath string, args []string, auth authOptions) error {
	mgr := viperadapter.NewManager(opts.ConfigPath)
	cfg, err := mgr.Load(cmd.Context())
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	email := cfg.Bitwarden.Email
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

	var passwordArgs []string
	if len(args) > 1 {
		passwordArgs = []string{args[1]}
	}
	if err := resolveLoginRegion(cmd, cfg, auth); err != nil {
		return err
	}

	cfg.Bitwarden.Email = email
	if err := coreconfig.Validate(cfg); err != nil {
		return err
	}
	if err := mgr.Save(cmd.Context(), cfg); err != nil {
		return fmt.Errorf("save login config: %w", err)
	}

	// Compose service BEFORE prompting for password/PIN so we can fail-fast
	// on keyring-unavailable without consuming stdin.
	svc, err := composeAppService(opts, cmd.Context(), cfg, cachePath, outboxPath)
	if err != nil {
		return fmt.Errorf("compose service: %w", err)
	}
	defer func() { _ = svc.Shutdown(context.Background()) }()

	status, statusErr := svc.AuthStatus(cmd.Context(), email)
	if statusErr != nil {
		return fmt.Errorf("auth status: %w", statusErr)
	}
	if status == session.KeyringUnavailable {
		return fmt.Errorf("Secret Service is required for login")
	}

	password, err := resolvePassword(cmd, passwordArgs, auth)
	if err != nil {
		return err
	}

	pin, err := promptPIN(cmd.InOrStdin(), cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	loginInput := coreauth.LoginInput{
		Email:           email,
		Password:        password,
		PIN:             pin,
		TwoFactorPrompt: promptTwoFactorCode(cmd),
	}
	if err := svc.Login(cmd.Context(), loginInput); err != nil {
		return err
	}

	if !auth.noSync {
		waitForInitialSync(cmd.Context(), svc.Events(), 30*time.Second)
	}

	if auth.raw {
		cmd.Println("login ok")
	} else {
		cmd.Println("You are logged in!")
	}
	return nil
}

func runUnlock(cmd *cobra.Command, opts Options, cachePath, outboxPath string, args []string, auth authOptions) error {
	mgr := viperadapter.NewManager(opts.ConfigPath)
	cfg, err := mgr.Load(cmd.Context())
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	email := cfg.Bitwarden.Email
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("no configured email; run `gtk4-layershell-bitwarden login <email>` first or set bitwarden.email")
	}

	// Resolve PIN from args, env, file, or prompt (not master password).
	pin, err := resolvePIN(cmd, args, auth)
	if err != nil {
		return err
	}

	svc, err := composeAppService(opts, cmd.Context(), cfg, cachePath, outboxPath)
	if err != nil {
		return fmt.Errorf("compose service: %w", err)
	}
	defer func() { _ = svc.Shutdown(context.Background()) }()

	if err := svc.UnlockWithPIN(cmd.Context(), email, pin); err != nil {
		return err
	}
	if !auth.noSync {
		waitForInitialSync(cmd.Context(), svc.Events(), 30*time.Second)
	}

	if auth.raw {
		cmd.Println("unlock ok")
	} else {
		cmd.Println("Your vault is now unlocked!")
	}
	return nil
}

func promptTwoFactorCode(cmd *cobra.Command) coreauth.TwoFactorPrompt {
	return func(ctx context.Context, providers []coreauth.TwoFactorProvider) (coreauth.TwoFactorProvider, string, bool, error) {
		provider := chooseTwoFactorProvider(providers)
		label := string(provider)
		if provider == coreauth.TwoFactorProviderAuthenticator {
			label = "authenticator code"
		}
		code, err := promptLine(cmd.InOrStdin(), cmd.ErrOrStderr(), fmt.Sprintf("Two-step login %s: ", label))
		if err != nil {
			return "", "", false, err
		}
		code = strings.TrimSpace(code)
		if code == "" {
			return "", "", false, fmt.Errorf("two-factor code is required")
		}
		return provider, code, false, ctx.Err()
	}
}

func chooseTwoFactorProvider(providers []coreauth.TwoFactorProvider) coreauth.TwoFactorProvider {
	for _, provider := range providers {
		if provider == coreauth.TwoFactorProviderAuthenticator {
			return provider
		}
	}
	if len(providers) > 0 {
		return providers[0]
	}
	return coreauth.TwoFactorProviderAuthenticator
}

func resolveLoginRegion(cmd *cobra.Command, cfg *coreconfig.Config, auth authOptions) error {
	region := strings.TrimSpace(auth.region)
	if region == "" {
		current := string(cfg.Bitwarden.Region)
		if current == "" {
			current = string(coreconfig.RegionUS)
		}
		answer, err := promptLine(cmd.InOrStdin(), cmd.ErrOrStderr(), fmt.Sprintf("Bitwarden region [us/eu/self_hosted] (%s): ", current))
		if err != nil {
			return err
		}
		region = strings.TrimSpace(answer)
		if region == "" {
			region = current
		}
	}

	switch coreconfig.Region(region) {
	case coreconfig.RegionUS, coreconfig.RegionEU:
		cfg.Bitwarden.Region = coreconfig.Region(region)
		cfg.Bitwarden.ServerURL = ""
	case coreconfig.RegionSelfHosted:
		cfg.Bitwarden.Region = coreconfig.RegionSelfHosted
		serverURL := strings.TrimSpace(auth.serverURL)
		if serverURL == "" {
			serverURL = strings.TrimSpace(cfg.Bitwarden.ServerURL)
		}
		if serverURL == "" {
			prompted, err := promptLine(cmd.InOrStdin(), cmd.ErrOrStderr(), "Self-hosted server URL (https://...): ")
			if err != nil {
				return err
			}
			serverURL = strings.TrimSpace(prompted)
		}
		cfg.Bitwarden.ServerURL = serverURL
	default:
		return fmt.Errorf("unsupported region %q: expected us, eu, or self_hosted", region)
	}
	return nil
}

// resolvePIN resolves the unlock PIN from positional args, --passwordenv,
// --passwordfile, or an interactive prompt.
func resolvePIN(cmd *cobra.Command, args []string, auth authOptions) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	if auth.passwordEnv != "" {
		value := os.Getenv(auth.passwordEnv)
		if value == "" {
			return "", fmt.Errorf("PIN environment variable %s is empty", auth.passwordEnv)
		}
		return strings.TrimRight(value, "\r\n"), nil
	}
	if auth.passwordFile != "" {
		data, err := os.ReadFile(auth.passwordFile)
		if err != nil {
			return "", fmt.Errorf("read PIN file: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}

	return promptPIN(cmd.InOrStdin(), cmd.ErrOrStderr())
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

	// Read byte-by-byte to avoid bufio.Reader buffering, which would
	// consume future prompt lines when multiple prompts share the same
	// underlying reader (e.g. PIN then 2FA).
	var buf [256]byte
	n := 0
	for n < len(buf) {
		var b [1]byte
		_, err := in.Read(b[:])
		if err != nil {
			if err == io.EOF && n > 0 {
				break
			}
			return "", err
		}
		if b[0] == '\n' {
			break
		}
		buf[n] = b[0]
		n++
	}
	return strings.TrimRight(string(buf[:n]), "\r"), nil
}

func promptPIN(in io.Reader, errOut io.Writer) (string, error) {
	return promptLine(in, errOut, "Local unlock PIN: ")
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

func newStatusCmd(opts Options, cachePath, outboxPath string) *cobra.Command {
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

			email := cfg.Bitwarden.Email
			resp := statusResponse{
				ServerURL: effectiveServerURL(cfg),
				UserEmail: email,
				Status:    string(session.Unauthenticated),
			}

			// Retrieve AuthStatus from the composed service when an email is configured.
			if email != "" {
				svc, serr := composeAppService(opts, cmd.Context(), cfg, cachePath, outboxPath)
				if serr != nil {
					return fmt.Errorf("compose service: %w", serr)
				}
				defer func() { _ = svc.Shutdown(context.Background()) }()

				statusStr, aerr := svc.AuthStatus(cmd.Context(), email)
				if aerr != nil && statusStr == "" {
					return aerr
				}
				resp.Status = string(statusStr)
			}

			// LastSync derived from cache file mtime.
			if info, serr := os.Stat(cachePath); serr == nil {
				resp.LastSync = info.ModTime().UTC().Format(time.RFC3339)
			}

			data, err := json.MarshalIndent(resp, "", "  ")
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

// newLockCmd deletes the local unlock envelope from the OS keyring so that
// a PIN is required to unlock again. The Bitwarden token bundle, encrypted
// cache, and outbox are left intact.
func newLockCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the local vault (clears unlock envelope)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := viperadapter.NewManager(opts.ConfigPath)
			cfg, err := mgr.Load(cmd.Context())
			if err != nil {
				return fmt.Errorf("config load: %w", err)
			}

			if cfg.Bitwarden.Email == "" {
				// No account configured; nothing to lock.
				cmd.Println("Local vault is already locked.")
				return nil
			}

			store := credentialStore(opts)
			if err := deleteUnlockEnvelopeForConfig(cmd.Context(), store, cfg); err != nil {
				return err
			}

			cmd.Println("Local unlock cleared.")
			return nil
		},
	}
}
