package cobra

import (
	"context"
	"fmt"

	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/session"
)

// forgetAccount signs the configured account out through the application
// service, deleting every stored credential for it.
func forgetAccount(ctx context.Context, opts Options, cfg *coreconfig.Config, cachePath, outboxPath string) error {
	svc, err := composeAppService(opts, ctx, cfg, cachePath, outboxPath)
	if err != nil {
		return fmt.Errorf("compose service: %w", err)
	}
	defer func() { _ = svc.Shutdown(context.WithoutCancel(ctx)) }()
	return svc.ForgetAccount(ctx, cfg.Bitwarden.Email)
}

// hardLockAccount deletes the unlock envelope of the configured account
// through the application service. Token bundle and PIN profile are kept.
func hardLockAccount(ctx context.Context, opts Options, cfg *coreconfig.Config, cachePath, outboxPath string) error {
	svc, err := composeAppService(opts, ctx, cfg, cachePath, outboxPath)
	if err != nil {
		return fmt.Errorf("compose service: %w", err)
	}
	defer func() { _ = svc.Shutdown(context.WithoutCancel(ctx)) }()
	return svc.HardLock(ctx, cfg.Bitwarden.Email)
}

// unlockBlockedMessage returns the CLI wording explaining why PIN unlock is not
// possible and what to run next. The decision itself comes from
// session.AuthStatusDetail.NextStep, shared with the GUI.
func unlockBlockedMessage(detail session.AuthStatusDetail) string {
	switch detail.NextStep() {
	case session.UnlockStepFixKeyring:
		return "secret service is required for unlock"
	case session.UnlockStepWait:
		return "too many PIN attempts; wait and retry"
	case session.UnlockStepLogin:
		return "not logged in; run `gtkls-bitwarden-client login <email>` first"
	case session.UnlockStepSetupPIN:
		return "no PIN profile configured; run `gtkls-bitwarden-client login <email>` to set up PIN unlock"
	case session.UnlockStepRenewEnvelope:
		switch detail.Reason {
		case session.AuthReasonNoEnvelope:
			return "no unlock envelope; run `gtkls-bitwarden-client login <email>` to create one, or use the GUI for envelope renewal"
		case session.AuthReasonBootChanged:
			return "system boot changed; renew unlock with master password (run GUI or login)"
		case session.AuthReasonAccountMismatch:
			return "account mismatch in envelope; renew unlock with master password (run GUI or login)"
		default:
			return "unlock envelope invalid; renew with master password (run GUI or login)"
		}
	default:
		return fmt.Sprintf("soft unlock not available (reason: %s, status: %s)", detail.Reason, detail.Status)
	}
}
