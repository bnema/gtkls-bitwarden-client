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
	pinEnv       string
	pinFile      string
	noSync       bool
	region       string
	serverURL    string
}

type statusResponse struct {
	ServerURL           string `json:"serverUrl,omitempty"`
	LastSync            string `json:"lastSync,omitempty"`
	UserEmail           string `json:"userEmail,omitempty"`
	Status              string `json:"status"`
	Reason              string `json:"reason"`
	HasPinProfile       bool   `json:"hasPinProfile"`
	HasEnvelope         bool   `json:"hasEnvelope"`
	EnvelopeValid       bool   `json:"envelopeValid"`
	SoftUnlockAvailable bool   `json:"softUnlockAvailable"`
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
	cmd.Flags().StringVar(&auth.pinEnv, "pinenv", "", "Environment variable containing the local unlock PIN")
	cmd.Flags().StringVar(&auth.pinFile, "pinfile", "", "File containing the local unlock PIN")
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
	defer func() { _ = svc.Shutdown(context.WithoutCancel(cmd.Context())) }()

	status, statusErr := svc.AuthStatus(cmd.Context(), email)
	if statusErr != nil {
		return fmt.Errorf("auth status: %w", statusErr)
	}
	if status == session.KeyringUnavailable {
		return fmt.Errorf("secret service is required for login")
	}

	password, err := resolvePassword(cmd, passwordArgs, auth)
	if err != nil {
		return err
	}

	// Resolve PIN: --pinenv/--pinfile skip interactive confirmation (Service.Login
	// still enforces min length). Interactive entry requires confirmation.
	// Note: Master password flags (--passwordenv/--passwordfile) do NOT trigger
	// this shortcut so PIN confirmation is not silently skipped.
	var pin string
	if auth.pinEnv != "" || auth.pinFile != "" {
		pin, err = resolvePIN(cmd, nil, auth)
		if err != nil {
			return err
		}
	} else {
		pin, err = promptPINWithConfirm(cmd.InOrStdin(), cmd.ErrOrStderr())
		if err != nil {
			return err
		}
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

	// Compose service and fail-fast on keyring-unavailable BEFORE consuming
	// PIN stdin (avoid consuming input when unlock is impossible).
	svc, err := composeAppService(opts, cmd.Context(), cfg, cachePath, outboxPath)
	if err != nil {
		return fmt.Errorf("compose service: %w", err)
	}
	defer func() { _ = svc.Shutdown(context.WithoutCancel(cmd.Context())) }()

	detail, detailErr := svc.AuthStatusDetail(cmd.Context(), email)
	if detailErr != nil {
		if detail.Status != session.KeyringUnavailable {
			return fmt.Errorf("auth status: %w", detailErr)
		}
		return fmt.Errorf("secret service is required for unlock")
	}

	// Fail-fast for any state where PIN unlock cannot succeed, before
	// consuming stdin.
	if !detail.SoftUnlockAvailable {
		msg := detailLockedMessage(detail)
		return fmt.Errorf("%s", msg)
	}

	// Resolve PIN from args, env, file, or prompt (not master password).
	pin, err := resolvePIN(cmd, args, auth)
	if err != nil {
		return err
	}

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

// detailLockedMessage returns a user-facing message explaining why PIN unlock
// is not available, based on the AuthStatusDetail. The message directs the user
// to the appropriate recovery path (login, renew via GUI, wait, etc.).
func detailLockedMessage(detail session.AuthStatusDetail) string {
	switch detail.Reason {
	case session.AuthReasonNoToken:
		return "not logged in; run `gtk4-layershell-bitwarden login <email>` first"
	case session.AuthReasonNoPINProfile:
		return "no PIN profile configured; run `gtk4-layershell-bitwarden login <email>` to set up PIN unlock"
	case session.AuthReasonNoEnvelope:
		return "no unlock envelope; run `gtk4-layershell-bitwarden login <email>` to create one, or use the GUI for envelope renewal"
	case session.AuthReasonEnvelopeExpired:
		return "unlock envelope expired; renew with master password (run GUI or login)"
	case session.AuthReasonBootChanged:
		return "system boot changed; renew unlock with master password (run GUI or login)"
	case session.AuthReasonPINBackoff:
		return "too many PIN attempts; wait and retry"
	case session.AuthReasonAccountMismatch:
		return "account mismatch in envelope; renew unlock with master password (run GUI or login)"
	case session.AuthReasonEnvelopeInvalid:
		return "unlock envelope invalid; renew with master password (run GUI or login)"
	case session.AuthReasonKeyringUnavailable:
		return "secret service is required for unlock"
	default:
		return fmt.Sprintf("soft unlock not available (reason: %s, status: %s)", detail.Reason, detail.Status)
	}
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

// resolvePIN resolves the unlock PIN from positional args, --pinenv,
// --pinfile, legacy --passwordenv/--passwordfile, or an interactive prompt.
func resolvePIN(cmd *cobra.Command, args []string, auth authOptions) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	if auth.pinEnv != "" {
		value := os.Getenv(auth.pinEnv)
		if value == "" {
			return "", fmt.Errorf("pin environment variable %s is empty", auth.pinEnv)
		}
		return strings.TrimRight(value, "\r\n"), nil
	}
	if auth.pinFile != "" {
		data, err := os.ReadFile(auth.pinFile)
		if err != nil {
			return "", fmt.Errorf("read pin file: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	// Backward compatibility for scripts that used the old generic flags for PIN unlock.
	if auth.passwordEnv != "" {
		value := os.Getenv(auth.passwordEnv)
		if value == "" {
			return "", fmt.Errorf("pin environment variable %s is empty", auth.passwordEnv)
		}
		return strings.TrimRight(value, "\r\n"), nil
	}
	if auth.passwordFile != "" {
		data, err := os.ReadFile(auth.passwordFile)
		if err != nil {
			return "", fmt.Errorf("read pin file: %w", err)
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

// promptPINWithConfirm prompts for a PIN interactively and requires a
// matching confirmation before returning. Mismatch is rejected before any
// remote login.
func promptPINWithConfirm(in io.Reader, errOut io.Writer) (string, error) {
	pin, err := promptPIN(in, errOut)
	if err != nil {
		return "", err
	}
	confirm, err := promptLine(in, errOut, "Confirm PIN: ")
	if err != nil {
		return "", err
	}
	if pin != confirm {
		return "", fmt.Errorf("PINs do not match")
	}
	return pin, nil
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

			// Retrieve AuthStatusDetail from the composed service when an email is configured.
			if email != "" {
				svc, serr := composeAppService(opts, cmd.Context(), cfg, cachePath, outboxPath)
				if serr != nil {
					return fmt.Errorf("compose service: %w", serr)
				}
				defer func() { _ = svc.Shutdown(context.WithoutCancel(cmd.Context())) }()

				detail, derr := svc.AuthStatusDetail(cmd.Context(), email)
				if derr != nil {
					if detail.Status != session.KeyringUnavailable {
						return derr
					}
				}
				resp.Status = string(detail.Status)
				resp.Reason = string(detail.Reason)
				resp.HasPinProfile = detail.HasPINProfile
				resp.HasEnvelope = detail.HasEnvelope
				resp.EnvelopeValid = detail.EnvelopeValid
				resp.SoftUnlockAvailable = detail.SoftUnlockAvailable
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

// newLockCmd locks the local vault. By default it performs a soft lock
// (clears resident process state only). With --hard, it also deletes the
// unlock envelope from the OS keyring.
func newLockCmd(opts Options) *cobra.Command {
	var hard bool
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Lock the local vault",
		Long:  "Lock the local vault. By default a soft lock is performed (clear process state only). Use --hard to also delete the unlock envelope.",
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

			if hard {
				// Hard lock: delete unlock envelope only (token + profile preserved).
				if err := deleteUnlockEnvelopeForConfig(cmd.Context(), store, cfg); err != nil {
					return fmt.Errorf("lock: %w", err)
				}
				cmd.Println("Local unlock envelope cleared.")
			} else {
				// Soft lock (default): local process state cleared. For a CLI process
				// there is no resident state to clear, so this is informational.
				cmd.Println("Local vault locked (soft lock).")
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&hard, "hard", false, "Perform a hard lock (delete unlock envelope)")
	return cmd
}
