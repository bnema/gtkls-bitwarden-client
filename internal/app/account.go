package app

import (
	"context"
	"fmt"
	"strings"
)

// ForgetAccount signs the account out of this device: it soft-locks the
// service and deletes the unlock envelope, token bundle, and PIN profile stored
// for email. Cached vault data is not touched; callers that want a full local
// wipe clear the cache and outbox separately.
//
// The credential store must be reachable; no credential is deleted when the
// availability check fails.
func (s *Service) ForgetAccount(ctx context.Context, email string) (retErr error) {
	log, started := logAppServiceStart(ctx, "forget_account")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("app: forget account: email is required")
	}

	if err := s.SoftLock(ctx); err != nil {
		return err
	}

	if err := s.checkCredentialsAvailable(ctx); err != nil {
		return fmt.Errorf("app: forget account: %w", err)
	}

	ref := s.accountRef(email)
	if err := s.deps.Credentials.DeleteUnlockEnvelope(ctx, ref); err != nil {
		return fmt.Errorf("app: forget account: delete unlock envelope: %w", err)
	}
	if err := s.deps.Credentials.DeleteTokenBundle(ctx, ref); err != nil {
		return fmt.Errorf("app: forget account: delete token bundle: %w", err)
	}
	if err := s.deps.Credentials.DeletePINProfile(ctx, ref); err != nil {
		return fmt.Errorf("app: forget account: delete pin profile: %w", err)
	}
	return nil
}
