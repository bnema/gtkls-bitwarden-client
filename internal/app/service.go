package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bnema/zerowrap"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	cerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	safelog "github.com/bnema/gtkls-bitwarden-client/internal/core/logging"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/session"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

const (
	// minPINLength is the minimum number of characters required for a
	// local unlock PIN.
	minPINLength = 4
)

func appServiceLog(ctx context.Context, operation string) zerowrap.Logger {
	return zerowrap.Logger{Logger: zerowrap.FromCtx(ctx).
		With().
		Str(zerowrap.FieldComponent, "app.service").
		Str(zerowrap.FieldOperation, operation).
		Logger()}
}

func logAppServiceStart(ctx context.Context, operation string) (zerowrap.Logger, time.Time) {
	log := appServiceLog(ctx, operation)
	log.Info().Msg("app service operation started")
	return log, time.Now()
}

func logAppServiceFinish(log zerowrap.Logger, started time.Time, err error) {
	event := log.Info()
	msg := "app service operation finished"
	if err != nil {
		event = log.Error().
			Str("error_kind", safelog.SafeErrorKind(err)).
			Str("error_detail", safelog.SafeErrorDetail(err))
		msg = "app service operation failed"
	}
	event.Int64(zerowrap.FieldDuration, time.Since(started).Milliseconds()).Msg(msg)
}

func logAppServiceFinishCount(log zerowrap.Logger, started time.Time, err error, count int) {
	event := log.Info()
	msg := "app service operation finished"
	if err != nil {
		event = log.Error().
			Str("error_kind", safelog.SafeErrorKind(err)).
			Str("error_detail", safelog.SafeErrorDetail(err))
		msg = "app service operation failed"
	}
	event.
		Int("count", count).
		Int64(zerowrap.FieldDuration, time.Since(started).Milliseconds()).
		Msg(msg)
}

func logRemoteSuccessLocalLocked(ctx context.Context, operation string) {
	log := appServiceLog(ctx, operation)
	log.Warn().Msg("remote operation succeeded but service locked before local update")
}

// NewService creates a new Service with the given dependencies.
func NewService(deps Deps) *Service {
	cfg := deps.Config
	if cfg == nil {
		cfg = config.Default()
	}
	return &Service{
		cfg:    cfg,
		state:  auth.LockStateLocked,
		events: make(chan Event, 64),
		deps:   deps,
	}
}

// emit sends a non-blocking event to the events channel. Safe for concurrent
// use and safe to call after Shutdown.
func (s *Service) emit(kind EventKind, message string) {
	s.emitCount(kind, message, 0)
}

func (s *Service) emitCount(kind EventKind, message string, count int) {
	s.eventMu.RLock()
	closed := s.eventsClosed
	if !closed {
		select {
		case s.events <- Event{Kind: kind, Message: message, Count: count}:
		default:
		}
	}
	s.eventMu.RUnlock()
}

// Login authenticates with the remote Bitwarden server and stores the
// resulting token bundle and a PIN-protected unlock envelope in the OS
// keyring. It performs remote login exactly once and requires a non-empty
// PIN before any remote call.
func (s *Service) Login(ctx context.Context, input auth.LoginInput) (retErr error) {
	log, started := logAppServiceStart(ctx, "login")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	// 1. Validate credentials availability and dependencies before remote login.
	if err := s.checkCredentialsAvailable(ctx); err != nil {
		return fmt.Errorf("app: credentials: %w", err)
	}
	if s.deps.PINEnvelope == nil {
		return fmt.Errorf("app: login: %w", cerrors.ErrUnsupported)
	}
	if s.deps.BootID == nil {
		return fmt.Errorf("app: login: %w", cerrors.ErrUnsupported)
	}

	// 2. Validate PIN before any remote login.
	pin := strings.TrimSpace(input.PIN)
	if pin == "" {
		return fmt.Errorf("app: login: PIN is required")
	}
	if len(pin) < minPINLength {
		return fmt.Errorf("app: login: PIN must be at least %d characters", minPINLength)
	}

	// 3. Perform remote login and cache load exactly once.
	if err := s.unlock(ctx, input.Email, input.Password, input.TwoFactorPrompt); err != nil {
		return err
	}

	// Ensure local unlocked state/plaintext is cleared on any error after unlock.
	// Detach from cancellation while preserving logger values for cleanup.
	defer func() {
		if retErr != nil {
			_ = s.Lock(context.WithoutCancel(ctx))
		}
	}()

	// 4. Export session material and token bundle from the authenticated remote.
	material, tokens, err := s.deps.Remote.ExportSession(ctx)
	if err != nil {
		return fmt.Errorf("app: export session: %w", err)
	}
	defer material.Close()
	defer tokens.Close()

	// 5. Read cache key from service under lock; do not alias.
	s.mu.Lock()
	var cacheKey []byte
	if len(s.cacheKey) > 0 {
		cacheKey = make([]byte, len(s.cacheKey))
		copy(cacheKey, s.cacheKey)
	}
	s.mu.Unlock()

	// Build unlock material: preserve exported UserKey, add cache key.
	unlockMaterial := material.Clone()
	defer unlockMaterial.Close()
	if len(cacheKey) > 0 {
		unlockMaterial.CacheKey = cacheKey
	}

	// 6. Build account reference and fill token bundle metadata.
	ref := s.accountRef(input.Email)
	tokens.Email = ref.Email
	tokens.ServerURL = ref.ServerURL
	tokens.UpdatedAt = s.now()

	// 7. Get boot ID.
	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil {
		return fmt.Errorf("app: boot id: %w", err)
	}

	// 8. Create PIN profile with verifier hash and random envelope key.
	// The profile stores an Argon2id verifier of the human PIN (never the raw PIN)
	// and a high-entropy EnvelopeKey used to wrap the unlock envelope.
	profile, err := session.NewPINProfile(ref, tokens.AccountID, pin, s.now())
	if err != nil {
		return fmt.Errorf("app: create pin profile: %w", err)
	}
	defer profile.Close()

	// 9. Create unlock envelope using the profile's high-entropy EnvelopeKey
	// as the wrapping secret (not the raw human PIN).
	envSecret := envelopeKeyToSecret(profile.EnvelopeKey)
	envelope, err := s.deps.PINEnvelope.Create(ctx, ref, unlockMaterial, envSecret, bootID)
	if err != nil {
		return fmt.Errorf("app: create envelope: %w", err)
	}

	// Set AccountID from token bundle if available.
	if tokens.AccountID != "" {
		envelope.AccountID = tokens.AccountID
	}

	// 10. Persist token bundle, PIN profile, and unlock envelope atomically.
	// On any persistence failure, best-effort delete all partial state.
	if err := s.deps.Credentials.SaveTokenBundle(ctx, ref, tokens); err != nil {
		envelope.Close()
		return fmt.Errorf("app: save token bundle: %w", err)
	}
	if err := s.deps.Credentials.SavePINProfile(ctx, ref, profile); err != nil {
		_ = s.deps.Credentials.DeleteTokenBundle(ctx, ref)
		_ = s.deps.Credentials.DeletePINProfile(ctx, ref)
		_ = s.deps.Credentials.DeleteUnlockEnvelope(ctx, ref)
		envelope.Close()
		return fmt.Errorf("app: save pin profile: %w", err)
	}
	if err := s.deps.Credentials.SaveUnlockEnvelope(ctx, ref, envelope); err != nil {
		// Best-effort clean up token bundle and PIN profile on envelope save failure.
		_ = s.deps.Credentials.DeleteTokenBundle(ctx, ref)
		_ = s.deps.Credentials.DeletePINProfile(ctx, ref)
		envelope.Close()
		return fmt.Errorf("app: save unlock envelope: %w", err)
	}

	return nil
}

// UnlockWithPIN unlocks the vault using a previously-stored PIN unlock envelope.
// When a PINProfile exists, the human PIN is verified against the profile's
// Argon2id verifier and the envelope is opened with the profile's high-entropy
// EnvelopeKey. When the profile is missing (legacy/migration path), the envelope
// is opened with the human PIN and a new PINProfile is created and saved after
// success. On PIN mismatch, failure counters are persisted; after max failures
// the envelope is deleted.
func (s *Service) UnlockWithPIN(ctx context.Context, email, pin string) (retErr error) {
	log, started := logAppServiceStart(ctx, "unlock_pin")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	// 1. Validate dependencies.
	if err := s.checkCredentialsAvailable(ctx); err != nil {
		return fmt.Errorf("app: unlock-pin: credentials: %w", err)
	}
	if s.deps.BootID == nil {
		return fmt.Errorf("app: unlock-pin: %w", cerrors.ErrUnsupported)
	}
	if s.deps.PINEnvelope == nil {
		return fmt.Errorf("app: unlock-pin: %w", cerrors.ErrUnsupported)
	}
	if s.deps.Remote == nil {
		return fmt.Errorf("app: unlock-pin: %w", cerrors.ErrUnsupported)
	}

	// 2. Check service state.
	s.mu.Lock()
	if s.state != auth.LockStateLocked {
		s.mu.Unlock()
		return fmt.Errorf("app: cannot unlock in state %s", s.state)
	}
	s.state = auth.LockStateUnlocking
	s.lifecycle++
	token := s.lifecycle
	s.mu.Unlock()

	s.emit(Unlocking, "unlocking vault with PIN")

	// 3. Build account reference.
	ref := s.accountRef(email)

	// 4. Load and refresh token bundle.
	tokens, err := s.ensureFreshTokens(ctx, ref)
	if err != nil {
		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return err
	}

	// 5. Load PIN profile.
	pin = strings.TrimSpace(pin)
	profile, profileErr := s.deps.Credentials.LoadPINProfile(ctx, ref)
	profileExists := profileErr == nil
	if profileExists {
		defer profile.Close()
		if err := profile.Validate(ref); err != nil {
			s.mu.Lock()
			s.state = auth.LockStateLocked
			s.mu.Unlock()
			return fmt.Errorf("app: unlock-pin: validate pin profile: %w", err)
		}
	}
	if profileErr != nil && !errors.Is(profileErr, cerrors.ErrNotFound) {
		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return fmt.Errorf("app: unlock-pin: load pin profile: %w", profileErr)
	}

	// 6. Get boot ID.
	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil {
		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return fmt.Errorf("app: unlock-pin: boot id: %w", err)
	}

	// 7. Load unlock envelope.
	envelope, err := s.deps.Credentials.LoadUnlockEnvelope(ctx, ref)
	if err != nil {
		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return fmt.Errorf("app: unlock-pin: load envelope: %w", err)
	}

	var material session.UnlockMaterial
	var opened session.UnlockEnvelope
	var openErr error

	if profileExists {
		// 7a. Profile exists: verify human PIN against profile first.
		if !profile.VerifyPIN(pin) {
			// PIN wrong: call Open with human PIN to increment failure counters.
			material, opened, openErr = s.deps.PINEnvelope.Open(ctx, ref, envelope, pin, bootID)
		} else {
			// PIN correct: open envelope using the high-entropy EnvelopeKey,
			// not the raw human PIN.
			envSecret := envelopeKeyToSecret(profile.EnvelopeKey)
			material, opened, openErr = s.deps.PINEnvelope.Open(ctx, ref, envelope, envSecret, bootID)
		}
	} else {
		// 7b. Migration path: no profile, open envelope with raw human PIN.
		material, opened, openErr = s.deps.PINEnvelope.Open(ctx, ref, envelope, pin, bootID)
		if openErr == nil {
			// Success: create and save a PINProfile from this PIN, then
			// rewrap the legacy raw-PIN envelope with the profile EnvelopeKey
			// before marking unlocked. Without this replacement, the next
			// profile-backed PIN unlock would try to open a raw-PIN envelope
			// with the EnvelopeKey and fail.
			newProfile, perr := session.NewPINProfile(ref, tokens.AccountID, pin, s.now())
			if perr != nil {
				material.Close()
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return fmt.Errorf("app: unlock-pin: create migration profile: %w", perr)
			}
			defer newProfile.Close()
			if saveErr := s.deps.Credentials.SavePINProfile(ctx, ref, newProfile); saveErr != nil {
				material.Close()
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return fmt.Errorf("app: unlock-pin: save migration profile: %w", saveErr)
			}

			rewrapped, createErr := s.deps.PINEnvelope.Create(ctx, ref, material, envelopeKeyToSecret(newProfile.EnvelopeKey), bootID)
			if createErr != nil {
				_ = s.deps.Credentials.DeletePINProfile(ctx, ref)
				material.Close()
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return fmt.Errorf("app: unlock-pin: create migration envelope: %w", createErr)
			}
			if tokens.AccountID != "" {
				rewrapped.AccountID = tokens.AccountID
			}
			if saveErr := s.deps.Credentials.SaveUnlockEnvelope(ctx, ref, rewrapped); saveErr != nil {
				_ = s.deps.Credentials.DeletePINProfile(ctx, ref)
				rewrapped.Close()
				material.Close()
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return fmt.Errorf("app: unlock-pin: save migration envelope: %w", saveErr)
			}
			opened = rewrapped
		}
	}

	if openErr != nil {
		// Determine if failure counters changed (PIN-related error).
		countersChanged := opened.FailedAttempts > envelope.FailedAttempts ||
			opened.BackoffUntil != envelope.BackoffUntil

		if countersChanged {
			if opened.ShouldDeleteAfterFailures() {
				if delErr := s.deps.Credentials.DeleteUnlockEnvelope(ctx, ref); delErr != nil {
					s.mu.Lock()
					s.state = auth.LockStateLocked
					s.mu.Unlock()
					return fmt.Errorf("app: unlock-pin: delete envelope after max failures: %w", delErr)
				}
			} else {
				if saveErr := s.deps.Credentials.SaveUnlockEnvelope(ctx, ref, opened); saveErr != nil {
					s.mu.Lock()
					s.state = auth.LockStateLocked
					s.mu.Unlock()
					return fmt.Errorf("app: unlock-pin: save updated envelope after wrong PIN: %w", saveErr)
				}
			}
		}

		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return openErr
	}
	defer material.Close()
	defer opened.Close()

	// 8. Save updated envelope if failure counters changed (reset after success).
	if opened.FailedAttempts != envelope.FailedAttempts || opened.BackoffUntil != envelope.BackoffUntil {
		if saveErr := s.deps.Credentials.SaveUnlockEnvelope(ctx, ref, opened); saveErr != nil {
			s.mu.Lock()
			s.state = auth.LockStateLocked
			s.mu.Unlock()
			return fmt.Errorf("app: unlock-pin: save reset envelope after success: %w", saveErr)
		}
	}

	// 9. Restore remote session.
	if err := s.deps.Remote.RestoreSession(ctx, material, tokens); err != nil {
		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return fmt.Errorf("app: unlock-pin: restore session: %w", err)
	}

	// 10. Install local state.
	var workerCtx context.Context
	var cancel context.CancelFunc
	var startWorker bool

	s.mu.Lock()
	if s.lifecycle != token || s.state != auth.LockStateUnlocking {
		s.mu.Unlock()
		return fmt.Errorf("app: unlock lifecycle superseded: %w", context.Canceled)
	}

	// Copy cache key from material (derived during Login).
	s.zeroCacheKeyLocked()
	s.cacheKey = make([]byte, len(material.CacheKey))
	copy(s.cacheKey, material.CacheKey)
	s.state = auth.LockStateUnlocked
	// Cache-only needs a cache key: without one nothing could be persisted, so
	// an unlock whose material carries no cache key stays resident.
	mode := sessionCacheOnly
	if len(material.CacheKey) == 0 {
		mode = sessionResident
	}
	s.sessionMode = mode
	if s.backgroundSyncEnabledLocked() {
		workerCtx, cancel = context.WithCancel(context.WithoutCancel(ctx))
		s.cancelWorkers = cancel
		s.backgroundSyncActive = true
		s.backgroundSyncSuspended = false
		startWorker = true
	}
	s.mu.Unlock()

	if cached, loadErr := s.vaultCache().Open(ctx, material.CacheKey); loadErr == nil && len(cached.Conflicts) > 0 {
		s.mu.Lock()
		if s.lifecycle == token && s.state == auth.LockStateUnlocked {
			s.conflicts = append([]coresync.Conflict(nil), cached.Conflicts...)
		}
		s.mu.Unlock()
	}

	if startWorker {
		s.startBackgroundSyncWorker(workerCtx, mode)
	}

	return nil
}

// RenewUnlockEnvelope renews the quick-unlock envelope atomically.
// When an existing PIN profile is present, it requires only the master password
// (PIN is ignored) and recreates the envelope using the profile's high-entropy
// EnvelopeKey. When no profile exists, SetupNewPIN must be true and a valid
// new PIN is required to create a profile and envelope.
// On any persistence failure, partial credentials are cleaned up.
func (s *Service) RenewUnlockEnvelope(ctx context.Context, input auth.RenewEnvelopeInput) (retErr error) {
	log, started := logAppServiceStart(ctx, "renew_unlock_envelope")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	// 1. Validate dependencies and credentials availability.
	if err := s.checkCredentialsAvailable(ctx); err != nil {
		return fmt.Errorf("app: renew-envelope: credentials: %w", err)
	}
	if s.deps.PINEnvelope == nil {
		return fmt.Errorf("app: renew-envelope: %w", cerrors.ErrUnsupported)
	}
	if s.deps.BootID == nil {
		return fmt.Errorf("app: renew-envelope: %w", cerrors.ErrUnsupported)
	}
	if s.deps.Remote == nil {
		return fmt.Errorf("app: renew-envelope: %w", cerrors.ErrUnsupported)
	}

	// 2. Build account reference.
	ref := s.accountRef(input.Email)

	// 3. Load existing token bundle to verify the account is authenticated.
	_, err := s.deps.Credentials.LoadTokenBundle(ctx, ref)
	if err != nil {
		return fmt.Errorf("app: renew-envelope: load token bundle: %w", err)
	}

	// 4. Load existing PIN profile.
	profile, profileErr := s.deps.Credentials.LoadPINProfile(ctx, ref)
	profileExists := profileErr == nil
	if profileExists {
		defer profile.Close()
	}
	if profileErr != nil && !errors.Is(profileErr, cerrors.ErrNotFound) {
		return fmt.Errorf("app: renew-envelope: load pin profile: %w", profileErr)
	}

	var envKey []byte
	var needsProfileSave bool

	if profileExists {
		// Existing profile: use its EnvelopeKey for the new envelope.
		// No PIN is required.
		envKey = make([]byte, len(profile.EnvelopeKey))
		copy(envKey, profile.EnvelopeKey)
		defer clear(envKey)
	} else {
		// No profile: must set up a new one.
		if !input.SetupNewPIN {
			return fmt.Errorf("app: renew-envelope: no PIN profile exists; set SetupNewPIN=true and provide a PIN")
		}
		pin := strings.TrimSpace(input.PIN)
		if pin == "" {
			return fmt.Errorf("app: renew-envelope: PIN is required when setting up a new profile")
		}
		if len(pin) < minPINLength {
			return fmt.Errorf("app: renew-envelope: PIN must be at least %d characters", minPINLength)
		}

		// We'll create the profile after remote login when we know AccountID.
		envKey = nil // created during NewPINProfile below
	}

	// 5. Perform remote master-password unlock.
	if err := s.unlock(ctx, input.Email, input.Password, input.TwoFactorPrompt); err != nil {
		return err
	}

	// Ensure local unlocked state/plaintext is cleared on any error after unlock.
	// Detach from cancellation while preserving logger values for cleanup.
	defer func() {
		if retErr != nil {
			_ = s.Lock(context.WithoutCancel(ctx))
		}
	}()

	// 6. Export session material and token bundle.
	material, tokens, err := s.deps.Remote.ExportSession(ctx)
	if err != nil {
		return fmt.Errorf("app: renew-envelope: export session: %w", err)
	}
	defer material.Close()
	defer tokens.Close()

	// 7. Read cache key.
	s.mu.Lock()
	var cacheKey []byte
	if len(s.cacheKey) > 0 {
		cacheKey = make([]byte, len(s.cacheKey))
		copy(cacheKey, s.cacheKey)
		defer clear(cacheKey)
	}
	s.mu.Unlock()

	unlockMaterial := material.Clone()
	defer unlockMaterial.Close()
	if len(cacheKey) > 0 {
		unlockMaterial.CacheKey = cacheKey
	}

	// 8. Build token bundle metadata.
	tokens.Email = ref.Email
	tokens.ServerURL = ref.ServerURL
	tokens.UpdatedAt = s.now()

	// 9. Create profile if needed.
	var newProfile session.PINProfile
	if !profileExists {
		pin := strings.TrimSpace(input.PIN)
		newProfile, err = session.NewPINProfile(ref, tokens.AccountID, pin, s.now())
		if err != nil {
			return fmt.Errorf("app: renew-envelope: create pin profile: %w", err)
		}
		defer newProfile.Close()
		envKey = make([]byte, len(newProfile.EnvelopeKey))
		copy(envKey, newProfile.EnvelopeKey)
		defer clear(envKey)
		needsProfileSave = true
	}

	// 10. Get boot ID.
	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil {
		return fmt.Errorf("app: renew-envelope: boot id: %w", err)
	}

	// 11. Create unlock envelope using EnvelopeKey secret.
	envSecret := envelopeKeyToSecret(envKey)
	envelope, err := s.deps.PINEnvelope.Create(ctx, ref, unlockMaterial, envSecret, bootID)
	if err != nil {
		return fmt.Errorf("app: renew-envelope: create envelope: %w", err)
	}
	if tokens.AccountID != "" {
		envelope.AccountID = tokens.AccountID
	}

	// 12. Persist token bundle, profile (if new), and envelope. Renewal should
	// not delete pre-existing token/profile credentials on a partial write;
	// hard-lock recovery must remain recoverable if envelope renewal fails.
	if err := s.deps.Credentials.SaveTokenBundle(ctx, ref, tokens); err != nil {
		envelope.Close()
		return fmt.Errorf("app: renew-envelope: save token bundle: %w", err)
	}
	if needsProfileSave {
		if err := s.deps.Credentials.SavePINProfile(ctx, ref, newProfile); err != nil {
			_ = s.deps.Credentials.DeletePINProfile(ctx, ref)
			_ = s.deps.Credentials.DeleteUnlockEnvelope(ctx, ref)
			envelope.Close()
			return fmt.Errorf("app: renew-envelope: save pin profile: %w", err)
		}
	} else if profileExists {
		// Update profile metadata (UpdatedAt).
		updatedProfile := profile.Clone()
		updatedProfile.UpdatedAt = s.now()
		if tokens.AccountID != "" {
			updatedProfile.AccountID = tokens.AccountID
		}
		defer updatedProfile.Close()
		if err := s.deps.Credentials.SavePINProfile(ctx, ref, updatedProfile); err != nil {
			envelope.Close()
			return fmt.Errorf("app: renew-envelope: save updated profile: %w", err)
		}
	}
	if err := s.deps.Credentials.SaveUnlockEnvelope(ctx, ref, envelope); err != nil {
		_ = s.deps.Credentials.DeleteUnlockEnvelope(ctx, ref)
		if needsProfileSave {
			_ = s.deps.Credentials.DeletePINProfile(ctx, ref)
		}
		envelope.Close()
		return fmt.Errorf("app: renew-envelope: save unlock envelope: %w", err)
	}

	return nil
}

func (s *Service) unlock(ctx context.Context, email, password string, prompt auth.TwoFactorPrompt) (retErr error) {
	s.mu.Lock()
	if s.state != auth.LockStateLocked {
		s.mu.Unlock()
		return fmt.Errorf("app: cannot unlock in state %s", s.state)
	}
	s.state = auth.LockStateUnlocking
	s.lifecycle++
	token := s.lifecycle
	s.mu.Unlock()

	s.emit(Unlocking, "unlocking vault")

	// Login via remote if configured.
	if s.deps.Remote != nil {
		rememberedTwoFactorToken, err := s.loadRememberedTwoFactorToken(ctx, email)
		if err != nil {
			s.mu.Lock()
			s.state = auth.LockStateLocked
			s.mu.Unlock()
			return err
		}
		defer clear(rememberedTwoFactorToken)

		challenge, err := s.deps.Remote.BeginLogin(ctx, email, password, rememberedTwoFactorToken)
		if err != nil {
			s.mu.Lock()
			s.state = auth.LockStateLocked
			s.mu.Unlock()
			return fmt.Errorf("app: login failed: %w", err)
		}
		if challenge != nil {
			defer challenge.Close()
			if prompt == nil {
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return fmt.Errorf("app: login failed: two-factor authentication required: %w", cerrors.ErrUnauthenticated)
			}
			provider, code, remember, err := prompt(ctx, challenge.Providers)
			if err != nil {
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return err
			}
			if err := s.deps.Remote.CompleteTwoFactorLogin(ctx, challenge, provider, code, remember); err != nil {
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return fmt.Errorf("app: two-factor login failed: %w", err)
			}
		}
	}

	// Load cache data: derives key via Argon2id using salt from the encrypted
	// snapshot or a fresh random salt for first-run/no-cache flows.
	cacheKey, loadedData, loaded, err := s.vaultCache().OpenWithPassword(ctx, password)
	defer clear(cacheKey)
	if err != nil {
		// Non-fatal: we can still unlock without cache.
		s.emit(CacheLoaded, fmt.Sprintf("cache load skipped: %v", err))
	} else if loaded {
		s.emit(CacheLoaded, "cache loaded from disk")
	} else {
		s.emit(CacheLoaded, "no cache found")
	}

	// Re-acquire lock and install state if lifecycle token still matches.
	s.mu.Lock()
	if s.lifecycle != token || s.state != auth.LockStateUnlocking {
		s.mu.Unlock()
		// Another Lock/Unlock cycle happened, do not install.
		return fmt.Errorf("app: unlock lifecycle superseded: %w", context.Canceled)
	}

	// Install cache data.
	if loaded {
		s.items = loadedData.Items
		s.folders = loadedData.Folders
		s.outbox = loadedData.Outbox
		s.conflicts = loadedData.Conflicts
	}
	// Copy cache key for outbox persistence.
	s.cacheKey = make([]byte, len(cacheKey))
	copy(s.cacheKey, cacheKey)
	s.cacheSalt = append(s.cacheSalt[:0], loadedData.Salt...)
	s.state = auth.LockStateUnlocked
	s.sessionMode = sessionResident

	if loaded {
		s.emit(IndexReady, "search index ready")
	}

	var workerCtx context.Context
	var cancel context.CancelFunc
	var startWorker bool
	if s.backgroundSyncEnabledLocked() {
		// Start background sync worker detached from cancellation while preserving logger values.
		workerCtx, cancel = context.WithCancel(context.WithoutCancel(ctx))
		s.cancelWorkers = cancel
		s.backgroundSyncActive = true
		s.backgroundSyncSuspended = false
		s.emit(Unlocking, "starting sync worker")
		startWorker = true
	}
	s.mu.Unlock()

	if startWorker {
		s.startBackgroundSyncWorker(workerCtx, sessionResident)
	}

	return nil
}

// Lock transitions the service from unlocked to locked. It is a compatibility
// wrapper around SoftLock.
func (s *Service) Lock(ctx context.Context) (retErr error) {
	log, started := logAppServiceStart(ctx, "lock")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	return s.SoftLock(ctx)
}

// SoftLock clears resident process state (items, folders, index, cache key,
// outbox, conflicts) and cancels background workers without deleting token
// bundle, PIN profile, unlock envelope, encrypted cache, or outbox from
// persistent storage.
func (s *Service) SoftLock(ctx context.Context) (retErr error) {
	log, started := logAppServiceStart(ctx, "soft_lock")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel background workers.
	if s.cancelWorkers != nil {
		s.cancelWorkers()
		s.cancelWorkers = nil
	}

	// Increment lifecycle to invalidate any in-flight unlock.
	s.lifecycle++

	// Clear cache key (zeroize before dropping).
	s.zeroCacheKeyLocked()

	// Clear pending remote state.
	s.pendingRemoteItems = nil
	s.pendingRemoteFolders = nil

	// Clear in-memory state.
	s.items = nil
	s.folders = nil
	s.index = nil
	s.outbox = nil
	s.conflicts = nil
	s.sessionMode = sessionResident
	s.backgroundSyncActive = false
	s.backgroundSyncSuspended = false
	s.state = auth.LockStateLocked

	s.emit(Relocked, "vault relocked")

	// Notify remote if available.
	if s.deps.Remote != nil {
		if err := s.deps.Remote.Lock(ctx); err != nil {
			return fmt.Errorf("app: remote lock failed: %w", err)
		}
	}

	return nil
}

// HardLock performs a soft lock and deletes the unlock envelope for the given
// email. The token bundle and PIN profile are preserved, allowing the user to
// renew the envelope with their master password via RenewUnlockEnvelope.
func (s *Service) HardLock(ctx context.Context, email string) (retErr error) {
	log, started := logAppServiceStart(ctx, "hard_lock")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	if err := s.SoftLock(ctx); err != nil {
		return err
	}

	if err := s.checkCredentialsAvailable(ctx); err != nil {
		return fmt.Errorf("app: hard-lock: %w", err)
	}

	ref := s.accountRef(email)
	if err := s.deps.Credentials.DeleteUnlockEnvelope(ctx, ref); err != nil {
		return fmt.Errorf("app: hard-lock: delete envelope: %w", err)
	}

	return nil
}

// Search searches vault items by query. Returns ErrLocked if not unlocked.
// Resident sessions (password unlock) search resident items; cache-only
// sessions (PIN unlock) search the encrypted cache. A local search index is built for the
// query and discarded afterward; no resident index is consulted or modified.
func (s *Service) Search(ctx context.Context, query string, limit int) ([]vault.ScoredItem, error) {
	items, err := s.unlockedItems(ctx)
	if err != nil {
		return nil, err
	}

	if len(items) == 0 {
		return nil, nil
	}

	// Build a local index scoped to this call; do not install on Service.
	idx := vault.BuildIndex(items)
	return idx.Search(query, limit), nil
}

// Items returns a copy of all vault items. Returns ErrLocked if not unlocked.
// Resident sessions return resident items; cache-only sessions read the
// encrypted cache.
func (s *Service) Items(ctx context.Context) ([]vault.Item, error) {
	items, err := s.unlockedItems(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]vault.Item, len(items))
	copy(result, items)
	return result, nil
}

// Conflicts returns a copy of unresolved sync conflicts. It exposes only
// conflict metadata needed to drive resolution UI, never vault item fields.
func (s *Service) Conflicts(ctx context.Context) ([]coresync.Conflict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != auth.LockStateUnlocked {
		return nil, cerrors.ErrLocked
	}
	result := make([]coresync.Conflict, len(s.conflicts))
	copy(result, s.conflicts)
	return result, nil
}

// ConflictDetail returns the best available local and remote snapshots for one
// unresolved conflict. It returns copies so callers cannot mutate service state.
func (s *Service) ConflictDetail(ctx context.Context, conflictID string) (coresync.ConflictDetail, error) {
	s.mu.Lock()
	if s.state != auth.LockStateUnlocked {
		s.mu.Unlock()
		return coresync.ConflictDetail{}, cerrors.ErrLocked
	}
	conflict, ok := findConflictByID(s.conflicts, conflictID)
	if !ok {
		s.mu.Unlock()
		return coresync.ConflictDetail{}, cerrors.ErrNotFound
	}
	view := s.sessionViewLocked(true)
	s.mu.Unlock()
	defer view.close()

	snap, err := view.load(ctx, s.vaultCache())
	if err != nil {
		return coresync.ConflictDetail{}, err
	}
	localItems := snap.Items
	outbox := snap.Outbox
	remoteItems := snap.PendingRemote

	if len(remoteItems) == 0 && conflict.Reason != coresync.ConflictRemoteDeleted && s.deps.Remote != nil {
		items, _, _, err := s.deps.Remote.Sync(ctx)
		if err == nil {
			remoteItems = cloneVaultItems(items)
		}
	}

	return conflictDetailFromSnapshots(conflict, localItems, remoteItems, outbox), nil
}

// Get returns a single vault item by ID from resident state (resident
// sessions) or the encrypted cache (cache-only sessions). Returns ErrNotFound
// when the item is not found.
func (s *Service) Get(ctx context.Context, id string) (vault.Item, error) {
	items, err := s.unlockedItems(ctx)
	if err != nil {
		return vault.Item{}, err
	}

	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}

	return vault.Item{}, cerrors.ErrNotFound
}

// Config returns a copy of the current configuration.
// The caller receives a freshly allocated copy that cannot mutate the
// service's internal config.
func (s *Service) Config() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return config.Default()
	}
	copied := *s.cfg
	return &copied
}

// Events returns a read-only channel of domain events.
func (s *Service) Events() <-chan Event {
	return s.events
}

// UpdateConfig replaces the current configuration with a validated copy.
// The only validation error tolerated is ErrEmailRequired (matching Load
// semantics), allowing first-run or hot-reload scenarios without email.
func (s *Service) UpdateConfig(ctx context.Context, cfg *config.Config) (retErr error) {
	log, started := logAppServiceStart(ctx, "update_config")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	if err := ctx.Err(); err != nil {
		return err
	}

	// Validate; tolerate only ErrEmailRequired (same as Load semantics).
	if err := config.Validate(cfg); err != nil {
		if errors.Is(err, config.ErrEmailRequired) {
			errs := config.ValidateAll(cfg)
			onlyEmail := true
			for _, e := range errs {
				if !errors.Is(e, config.ErrEmailRequired) {
					onlyEmail = false
					break
				}
			}
			if !onlyEmail {
				return fmt.Errorf("config update: %w", err)
			}
		} else {
			return fmt.Errorf("config update: %w", err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	copied := *cfg
	s.cfg = &copied
	s.deps.Config = &copied

	s.emit(SyncUpdated, "config updated")
	return nil
}

// Shutdown gracefully shuts down the service.
func (s *Service) Shutdown(ctx context.Context) (retErr error) {
	log, started := logAppServiceStart(ctx, "shutdown")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	s.mu.Lock()
	if s.cancelWorkers != nil {
		s.cancelWorkers()
		s.cancelWorkers = nil
	}
	// Clear state under s.mu.
	s.items = nil
	s.folders = nil
	s.index = nil
	s.outbox = nil
	s.conflicts = nil
	s.pendingRemoteItems = nil
	s.pendingRemoteFolders = nil
	s.zeroCacheKeyLocked()
	s.sessionMode = sessionResident
	s.backgroundSyncActive = false
	s.backgroundSyncSuspended = false
	s.state = auth.LockStateLocked
	s.mu.Unlock()

	savesDone := make(chan struct{})
	go func() {
		s.saveWG.Wait()
		close(savesDone)
	}()
	select {
	case <-savesDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	s.eventMu.Lock()
	if !s.eventsClosed {
		close(s.events)
		s.eventsClosed = true
	}
	s.eventMu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------------

// envelopeKeyToSecret converts the 32-byte high-entropy EnvelopeKey from a
// PINProfile to an opaque hex-encoded string suitable for
// PINEnvelopeService.Create/Open. The key is never derived from the human
// PIN; it is a random secret stored in Secret Service.
func envelopeKeyToSecret(key []byte) string {
	return hex.EncodeToString(key)
}

// ensureUnlocked returns ErrLocked if the service is not in the unlocked state.
// Caller must hold s.mu.
func (s *Service) ensureUnlocked() error {
	if s.state != auth.LockStateUnlocked {
		return cerrors.ErrLocked
	}
	return nil
}

// now returns the current time, using deps.Clock if available.
func (s *Service) now() time.Time {
	if s.deps.Clock != nil {
		return s.deps.Clock.Now()
	}
	return time.Now()
}

// rebuildIndexLocked clears the resident search index. Callers invoke it
// after mutation/sync changes; search, items, and get build transient local
// indexes per call to avoid retaining plaintext in memory. The caller must
// hold s.mu.
func (s *Service) rebuildIndexLocked() {
	s.index = nil
}

// zeroCacheKeyLocked zeroes the cacheKey slice and sets it to nil.
// The caller must hold s.mu.
func (s *Service) zeroCacheKeyLocked() {
	if s.cacheKey != nil {
		for i := range s.cacheKey {
			s.cacheKey[i] = 0
		}
		s.cacheKey = nil
	}
	if s.cacheSalt != nil {
		for i := range s.cacheSalt {
			s.cacheSalt[i] = 0
		}
		s.cacheSalt = nil
	}
}

// newOutboxMutationLocked builds an outbox mutation with a fresh ID. The
// caller MUST hold s.mu and is responsible for queueing it.
func (s *Service) newOutboxMutationLocked(kind coresync.MutationKind, itemID string, payload []byte) coresync.OutboxMutation {
	s.outboxSeq++
	return coresync.OutboxMutation{
		ID:        fmt.Sprintf("m-%d-%d", s.now().UnixNano(), s.outboxSeq),
		Kind:      kind,
		ItemID:    itemID,
		CreatedAt: s.now(),
		Payload:   payload,
	}
}

// appendOutboxLocked appends a mutation to the resident outbox and persists
// it. It is for resident sessions only; cache-only sessions queue through the
// encrypted cache (see saveCacheMutationAsyncLocked). The caller must hold
// s.mu.
func (s *Service) appendOutboxLocked(ctx context.Context, m coresync.OutboxMutation) {
	s.outbox = append(s.outbox, m)
	s.saveCacheAsyncLocked(ctx)
}

// removeReplayedOutboxLocked removes only the mutations that were replayed.
// The caller must hold s.mu.
func (s *Service) removeReplayedOutboxLocked(replayed []coresync.OutboxMutation) {
	if len(replayed) == 0 || len(s.outbox) == 0 {
		return
	}
	replayedIDs := make(map[string]struct{}, len(replayed))
	for _, mutation := range replayed {
		replayedIDs[mutation.ID] = struct{}{}
	}
	kept := s.outbox[:0]
	for _, mutation := range s.outbox {
		if _, ok := replayedIDs[mutation.ID]; !ok {
			kept = append(kept, mutation)
		}
	}
	s.outbox = kept
}

// saveCacheAsyncLocked snapshots decrypted state, then asynchronously persists
// encrypted cache and encrypted outbox stores. The caller MUST hold s.mu.
func (s *Service) saveCacheAsyncLocked(ctx context.Context) {
	s.saveCacheSnapshotAsyncLocked(ctx, nil)
}

// saveCacheMutationAsyncLocked patches the encrypted cache from its current
// contents rather than from resident s.items. This preserves PIN-unlocked
// sessions, where resident plaintext intentionally stays empty/partial.
// The caller MUST hold s.mu.
func (s *Service) saveCacheMutationAsyncLocked(ctx context.Context, mutate func(*decryptedCacheSnapshot)) {
	s.saveCacheSnapshotAsyncLocked(ctx, mutate)
}

// saveCacheSnapshotAsyncLocked snapshots the current key/outbox and persists
// cache state asynchronously. If mutate is non-nil, items/folders are loaded
// from the existing encrypted cache and handed to mutate, then saved back;
// otherwise resident s.items/s.folders are snapshotted. In a cache-only
// session the outbox is loaded from the cache as well (the resident outbox is
// empty there), so mutate also sees and extends the persisted outbox. The
// caller MUST hold s.mu.
func (s *Service) saveCacheSnapshotAsyncLocked(ctx context.Context, mutate func(*decryptedCacheSnapshot)) {
	s.saveSeq++
	seq := s.saveSeq
	cacheOnly := s.sessionMode.cacheOnly()
	lifecycle := s.lifecycle
	key := make([]byte, len(s.cacheKey))
	copy(key, s.cacheKey)
	salt := make([]byte, len(s.cacheSalt))
	copy(salt, s.cacheSalt)
	itemsSnap := make([]vault.Item, len(s.items))
	copy(itemsSnap, s.items)
	foldersSnap := make([]vault.Folder, len(s.folders))
	copy(foldersSnap, s.folders)
	outboxSnap := make([]coresync.OutboxMutation, len(s.outbox))
	copy(outboxSnap, s.outbox)
	conflictsSnap := make([]coresync.Conflict, len(s.conflicts))
	copy(conflictsSnap, s.conflicts)
	vc := s.vaultCache()
	accountHash := s.accountHashLocked()

	if len(key) == 0 {
		return
	}
	// A cache-only session persists its outbox from the cache contents below.
	outboxFromCache := cacheOnly && mutate != nil
	if outboxFromCache {
		s.cachePatches = append(s.cachePatches, cachePatch{lifecycle: lifecycle, apply: mutate})
	}

	s.saveWG.Go(func() {
		defer clear(key)

		s.cacheSaveMu.Lock()
		defer s.cacheSaveMu.Unlock()

		// The seq/s.saveSeq check runs after cacheSaveMu to skip redundant I/O
		// if a newer save was queued while this goroutine waited. The newer
		// goroutine owns the durable write; Shutdown waits on saveWG, and each
		// save has a bounded timeout, so skipping stale snapshots is intentional.
		//
		// Cache-only patches are deltas, not snapshots: they are never dropped.
		// Whichever save runs first applies every queued patch in order, and a
		// save that finds the queue empty has nothing left to do.
		s.mu.Lock()
		stale := seq != s.saveSeq
		var patches []cachePatch
		if outboxFromCache {
			patches = s.takeCachePatchesLocked(lifecycle)
			stale = len(patches) == 0
		}
		s.mu.Unlock()
		if stale {
			return
		}

		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		if vc.outbox != nil && !outboxFromCache {
			// Persist the encrypted outbox independently of cache item patching. If
			// mutate later cannot load the item cache, keeping outbox durable is
			// still preferable to losing queued local mutations.
			outboxLog, outboxStarted := logAppServiceStart(cleanupCtx, "save_outbox")
			err := vc.SaveOutbox(cleanupCtx, key, outboxSnap)
			logAppServiceFinishCount(outboxLog, outboxStarted, err, len(outboxSnap))
		}

		cacheLog, cacheStarted := logAppServiceStart(cleanupCtx, "save_cache")
		data := decryptedCacheSnapshot{
			Salt:      salt,
			Items:     itemsSnap,
			Folders:   foldersSnap,
			Outbox:    outboxSnap,
			Conflicts: conflictsSnap,
		}
		if mutate != nil && (vc.Available() || outboxFromCache) {
			loaded, loadErr := vc.Open(cleanupCtx, key)
			if loadErr != nil {
				cacheLog.Warn().
					Str("error_kind", safelog.SafeErrorKind(loadErr)).
					Msg("skipping cache save: failed to load existing cache for mutation")
				logAppServiceFinishCount(cacheLog, cacheStarted, loadErr, 0)
				if outboxFromCache {
					s.recoverCachePatches(cleanupCtx, vc, key, patches)
				}
				return
			}
			if len(data.Salt) == 0 {
				data.Salt = loaded.Salt
			}
			data.Items = loaded.Items
			// Keep folders from the encrypted cache, not resident s.folders: PIN
			// unlock sessions intentionally keep resident vault state empty.
			data.Folders = loaded.Folders
			if outboxFromCache {
				data.Outbox = loaded.Outbox
			}
			if outboxFromCache {
				applyCachePatches(&data, patches)
			} else {
				mutate(&data)
			}
			if outboxFromCache {
				outboxLog, outboxStarted := logAppServiceStart(cleanupCtx, "save_outbox")
				err := vc.SaveOutbox(cleanupCtx, key, data.Outbox)
				logAppServiceFinishCount(outboxLog, outboxStarted, err, len(data.Outbox))
			}
		}

		if !vc.Available() {
			return
		}

		err := vc.Save(cleanupCtx, key, accountHash, data)
		if errors.Is(err, errNoCacheSalt) {
			cacheLog.Warn().Msg("no cache salt recovered; skipping cache save")
			return
		}
		logAppServiceFinishCount(cacheLog, cacheStarted, err, len(data.Items)+len(data.Folders)+len(data.Outbox))
	})
}

// takeCachePatchesLocked removes and returns the queued patches of the given
// session, in order, leaving other sessions' patches queued. The caller MUST
// hold s.mu.
func (s *Service) takeCachePatchesLocked(lifecycle uint64) []cachePatch {
	var mine []cachePatch
	kept := s.cachePatches[:0]
	for _, p := range s.cachePatches {
		if p.lifecycle == lifecycle {
			mine = append(mine, p)
		} else {
			kept = append(kept, p)
		}
	}
	s.cachePatches = kept
	return mine
}

// applyCachePatches applies queued cache-only patches in order. A patch that
// was already persisted by an earlier failed flush (see recoverCachePatches)
// may run again, so the outbox is deduplicated by mutation ID afterwards; the
// item effects of every kind are idempotent.
func applyCachePatches(data *decryptedCacheSnapshot, patches []cachePatch) {
	for _, patch := range patches {
		patch.apply(data)
	}
	data.Outbox = dedupeOutboxMutations(data.Outbox)
}

// recoverCachePatches handles a cache-only flush that could not read the
// encrypted cache. The patches are put back at the front of the queue so the
// next flush retries them, and their outbox entries are made durable now by
// merging them into the standalone outbox store, which does not depend on the
// item cache. If that store cannot be read either, nothing is written (a
// partial outbox would overwrite queued mutations) and the queue is the only
// copy until the next flush.
func (s *Service) recoverCachePatches(ctx context.Context, vc vaultCache, key []byte, patches []cachePatch) {
	s.mu.Lock()
	s.cachePatches = append(patches, s.cachePatches...)
	s.mu.Unlock()

	if vc.outbox == nil || len(key) == 0 {
		return
	}
	stored, err := vc.outbox.Load(ctx, key)
	if err != nil {
		return
	}
	// Item effects land on an empty list and are discarded; only the outbox
	// is kept.
	data := decryptedCacheSnapshot{Outbox: append([]coresync.OutboxMutation(nil), stored...)}
	applyCachePatches(&data, patches)
	log, started := logAppServiceStart(ctx, "save_outbox")
	err = vc.SaveOutbox(ctx, key, data.Outbox)
	logAppServiceFinishCount(log, started, err, len(data.Outbox))
}

func upsertVaultItem(items []vault.Item, item vault.Item) []vault.Item {
	return upsertVaultItemAs(items, item.ID, item)
}

// upsertVaultItemAs returns a copy of items in which the entry with ID key is
// replaced by item, or item is appended if no entry has that ID.
func upsertVaultItemAs(items []vault.Item, key string, item vault.Item) []vault.Item {
	out := make([]vault.Item, len(items), len(items)+1)
	copy(out, items)
	for i, existing := range out {
		if existing.ID == key {
			out[i] = item
			return out
		}
	}
	return append(out, item)
}

func findConflictByID(conflicts []coresync.Conflict, id string) (coresync.Conflict, bool) {
	for _, conflict := range conflicts {
		if conflict.ID == id {
			return conflict, true
		}
	}
	return coresync.Conflict{}, false
}

func removeConflictsForItem(conflicts []coresync.Conflict, itemID string) []coresync.Conflict {
	if len(conflicts) == 0 {
		return conflicts
	}
	kept := make([]coresync.Conflict, 0, len(conflicts))
	for _, conflict := range conflicts {
		if conflict.ItemID != itemID {
			kept = append(kept, conflict)
		}
	}
	return kept
}

func replaceConflictsForItems(existing, detected []coresync.Conflict) []coresync.Conflict {
	if len(detected) == 0 {
		return existing
	}
	affectedItems := make(map[string]struct{}, len(detected))
	for _, conflict := range detected {
		affectedItems[conflict.ItemID] = struct{}{}
	}
	out := existing[:0]
	for _, conflict := range existing {
		if _, affected := affectedItems[conflict.ItemID]; !affected {
			out = append(out, conflict)
		}
	}
	seen := make(map[string]struct{}, len(detected))
	for _, conflict := range detected {
		if _, ok := seen[conflict.ID]; ok {
			continue
		}
		seen[conflict.ID] = struct{}{}
		out = append(out, conflict)
	}
	return out
}

func cloneVaultItems(items []vault.Item) []vault.Item {
	if items == nil {
		return nil
	}
	out := make([]vault.Item, len(items))
	for i, item := range items {
		out[i] = cloneVaultItem(item)
	}
	return out
}

func cloneVaultItem(item vault.Item) vault.Item {
	clone := item
	if item.Login != nil {
		login := *item.Login
		login.URIs = append([]vault.URI(nil), item.Login.URIs...)
		clone.Login = &login
	}
	if item.SecureNote != nil {
		secureNote := *item.SecureNote
		clone.SecureNote = &secureNote
	}
	if item.Card != nil {
		card := *item.Card
		clone.Card = &card
	}
	if item.Identity != nil {
		identity := *item.Identity
		clone.Identity = &identity
	}
	clone.Fields = append([]vault.Field(nil), item.Fields...)
	clone.Attachments = append([]vault.Attachment(nil), item.Attachments...)
	return clone
}

func conflictDetailFromSnapshots(conflict coresync.Conflict, localItems, remoteItems []vault.Item, outbox []coresync.OutboxMutation) coresync.ConflictDetail {
	detail := coresync.ConflictDetail{Conflict: conflict}
	for _, item := range localItems {
		if item.ID == conflict.ItemID {
			local := cloneVaultItem(item)
			detail.LocalItem = &local
			break
		}
	}
	for _, item := range remoteItems {
		if item.ID == conflict.ItemID {
			remote := cloneVaultItem(item)
			remote.SyncStatus = vault.SyncStatusSynced
			remote.ConflictID = ""
			detail.RemoteItem = &remote
			break
		}
	}
	if detail.LocalItem == nil {
		if item, ok := itemFromConflictMutation(conflict, outbox); ok {
			detail.LocalItem = &item
		}
	}
	mutationKind := conflictMutationKind(conflict, outbox)
	detail.LocalDeleted = mutationKind == coresync.MutationDelete || mutationKind == coresync.MutationTrash
	detail.RemoteDeleted = conflict.Reason == coresync.ConflictRemoteDeleted
	return detail
}

func itemFromConflictMutation(conflict coresync.Conflict, outbox []coresync.OutboxMutation) (vault.Item, bool) {
	for _, mutation := range outbox {
		if mutation.ID != conflict.MutationID && mutation.ItemID != conflict.ItemID {
			continue
		}
		if mutation.Kind != coresync.MutationCreate && mutation.Kind != coresync.MutationUpdate {
			continue
		}
		var item vault.Item
		if err := json.Unmarshal(mutation.Payload, &item); err != nil {
			return vault.Item{}, false
		}
		if item.ID == "" {
			item.ID = mutation.ItemID
		}
		item.SyncStatus = vault.SyncStatusConflict
		item.ConflictID = conflict.ID
		return cloneVaultItem(item), true
	}
	return vault.Item{}, false
}

func conflictMutationKind(conflict coresync.Conflict, outbox []coresync.OutboxMutation) coresync.MutationKind {
	for _, mutation := range outbox {
		if mutation.ID == conflict.MutationID || mutation.ItemID == conflict.ItemID {
			return mutation.Kind
		}
	}
	return ""
}

func revisionForItem(items []vault.Item, id string) string {
	for _, item := range items {
		if item.ID == id && !item.RevisionDate.IsZero() {
			return item.RevisionDate.Format(time.RFC3339)
		}
	}
	return ""
}

func setOutboxBaseRevisionForItem(outbox []coresync.OutboxMutation, itemID, revision string) {
	for i := range outbox {
		if outbox[i].ItemID == itemID {
			outbox[i].BaseRevision = revision
		}
	}
}

func removeVaultItem(items []vault.Item, id string) []vault.Item {
	out := make([]vault.Item, 0, len(items))
	for _, item := range items {
		if item.ID != id {
			out = append(out, item)
		}
	}
	return out
}

func removeOutboxMutationsForItem(outbox []coresync.OutboxMutation, itemID string) []coresync.OutboxMutation {
	kept := make([]coresync.OutboxMutation, 0, len(outbox))
	for _, mutation := range outbox {
		if mutation.ItemID != itemID {
			kept = append(kept, mutation)
		}
	}
	return kept
}

func (s *Service) accountHashLocked() string {
	email := ""
	if s.cfg != nil {
		email = s.cfg.Bitwarden.Email
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return fmt.Sprintf("%x", sum[:])
}

// ---------------------------------------------------------------------------
// Auth status helpers
// ---------------------------------------------------------------------------

const (
	refreshBeforeExpiry = 2 * time.Minute
)

// accountRef builds a session.AccountRef from the given email and the
// effective server URL derived from the current configuration.
func (s *Service) accountRef(email string) session.AccountRef {
	return session.AccountRef{
		Email:     strings.ToLower(strings.TrimSpace(email)),
		ServerURL: s.effectiveServerURL(),
	}
}

func (s *Service) loadRememberedTwoFactorToken(ctx context.Context, email string) ([]byte, error) {
	if s.deps.Credentials == nil {
		return nil, nil
	}
	bundle, err := s.deps.Credentials.LoadTokenBundle(ctx, s.accountRef(email))
	if err != nil {
		if errors.Is(err, cerrors.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("app: load remembered two-factor token: %w", err)
	}
	defer bundle.Close()
	if len(bundle.RememberedTwoFactorToken) == 0 {
		return nil, nil
	}
	remembered := make([]byte, len(bundle.RememberedTwoFactorToken))
	copy(remembered, bundle.RememberedTwoFactorToken)
	return remembered, nil
}

// effectiveServerURL returns the current effective server URL based on config.
// Unexported for now; tests exercise it through accountRef and AuthStatus.
func (s *Service) effectiveServerURL() string {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	if cfg == nil {
		return "https://vault.bitwarden.com"
	}

	if cfg.Bitwarden.Region == config.RegionSelfHosted && cfg.Bitwarden.ServerURL != "" {
		return strings.TrimRight(cfg.Bitwarden.ServerURL, "/")
	}

	switch cfg.Bitwarden.Region {
	case config.RegionEU:
		return "https://vault.bitwarden.eu"
	default:
		return "https://vault.bitwarden.com"
	}
}

// checkCredentialsAvailable checks whether the credential store is available
// and healthy. Returns a validation error when s.deps.Credentials is nil, or
// the result of CheckAvailable otherwise.
func (s *Service) checkCredentialsAvailable(ctx context.Context) error {
	if s.deps.Credentials == nil {
		return cerrors.ErrUnsupported
	}
	return s.deps.Credentials.CheckAvailable(ctx)
}

// ensureFreshTokens loads the token bundle from the credential store and
// refreshes it when the access token is expired or within 2 minutes of expiry.
// On successful refresh, Email and ServerURL metadata are preserved and the
// updated bundle is saved back to the credential store.
//
// Error/save-back behavior:
//   - Token still valid for >2 minutes: return loaded bundle unchanged.
//   - Expired or near-expiry + refresh success: save, return updated bundle.
//   - Refresh returns unauthenticated / invalid grant: delete bundle, return error.
//   - Refresh returns transient / network / other: keep bundle, return error.
func (s *Service) ensureFreshTokens(ctx context.Context, ref session.AccountRef) (session.TokenBundle, error) {
	bundle, err := s.deps.Credentials.LoadTokenBundle(ctx, ref)
	if err != nil {
		return session.TokenBundle{}, fmt.Errorf("app: load token bundle: %w", err)
	}

	// If the token is still fresh (not zero and more than 2 minutes from now),
	// return the loaded bundle unchanged.
	if !bundle.ExpiresAt.IsZero() && time.Until(bundle.ExpiresAt) > refreshBeforeExpiry {
		return bundle, nil
	}

	// Token is expired or about to expire; attempt refresh.
	updated, err := s.deps.Remote.RefreshTokenBundle(ctx, bundle)
	if err != nil {
		if errors.Is(err, cerrors.ErrUnauthenticated) {
			// Invalid grant / unauthenticated — delete the token bundle.
			_ = s.deps.Credentials.DeleteTokenBundle(ctx, ref)
		}
		return session.TokenBundle{}, fmt.Errorf("app: refresh token bundle: %w", err)
	}

	// Preserve metadata from the original bundle.
	updated.Email = bundle.Email
	updated.ServerURL = bundle.ServerURL
	if len(updated.RememberedTwoFactorToken) == 0 && len(bundle.RememberedTwoFactorToken) > 0 {
		updated.RememberedTwoFactorToken = make([]byte, len(bundle.RememberedTwoFactorToken))
		copy(updated.RememberedTwoFactorToken, bundle.RememberedTwoFactorToken)
	}
	updated.UpdatedAt = s.now()

	if saveErr := s.deps.Credentials.SaveTokenBundle(ctx, ref, updated); saveErr != nil {
		return session.TokenBundle{}, fmt.Errorf("app: save refreshed token bundle: %w", saveErr)
	}

	return updated, nil
}

// AuthStatus reports the session authentication state for the given email.
func (s *Service) AuthStatus(ctx context.Context, email string) (session.AuthStatus, error) {
	detail, err := s.AuthStatusDetail(ctx, email)
	return detail.Status, err
}

// AuthStatusDetail returns detailed authentication state for the given email,
// including the status, reason, and presence/validity of token, PIN profile,
// and unlock envelope.
func (s *Service) AuthStatusDetail(ctx context.Context, email string) (detail session.AuthStatusDetail, retErr error) {
	log, started := logAppServiceStart(ctx, "auth_status_detail")
	var envelopeExpired bool
	var bootMatches bool
	defer func() {
		event := log.Info()
		msg := "app service operation finished"
		if retErr != nil {
			event = log.Error().Str("error_kind", safelog.SafeErrorKind(retErr))
			msg = "app service operation failed"
		}
		event.
			Int64(zerowrap.FieldDuration, time.Since(started).Milliseconds()).
			Str("status", string(detail.Status)).
			Bool("has_token_bundle", detail.HasToken).
			Bool("has_pin_profile", detail.HasPINProfile).
			Bool("has_envelope", detail.HasEnvelope).
			Bool("envelope_expired", envelopeExpired).
			Bool("boot_matches", bootMatches).
			Msg(msg)
	}()

	detail = session.AuthStatusDetail{}

	if err := s.checkCredentialsAvailable(ctx); err != nil {
		detail.Status = session.KeyringUnavailable
		detail.Reason = session.AuthReasonKeyringUnavailable
		return detail, err
	}

	ref := s.accountRef(email)

	// Load token bundle; if not found the user is unauthenticated.
	_, err := s.deps.Credentials.LoadTokenBundle(ctx, ref)
	if err != nil {
		if errors.Is(err, cerrors.ErrNotFound) {
			detail.Status = session.Unauthenticated
			detail.Reason = session.AuthReasonNoToken
			return detail, nil
		}
		detail.Status = session.KeyringUnavailable
		detail.Reason = session.AuthReasonKeyringUnavailable
		return detail, fmt.Errorf("app: load token bundle: %w", err)
	}
	detail.HasToken = true

	// Load PIN profile. A missing profile does not immediately make the
	// account locked: old envelope-only users can still PIN-unlock once and
	// lazily create the profile after the envelope opens successfully.
	profile, err := s.deps.Credentials.LoadPINProfile(ctx, ref)
	profileMissing := false
	if err != nil {
		if errors.Is(err, cerrors.ErrNotFound) {
			profileMissing = true
		} else {
			detail.Status = session.KeyringUnavailable
			detail.Reason = session.AuthReasonKeyringUnavailable
			return detail, fmt.Errorf("app: load pin profile: %w", err)
		}
	} else {
		defer profile.Close()
		detail.HasPINProfile = true
	}

	// Load unlock envelope; if missing the vault is locked.
	env, err := s.deps.Credentials.LoadUnlockEnvelope(ctx, ref)
	if err != nil {
		if errors.Is(err, cerrors.ErrNotFound) {
			detail.Status = session.LoggedInLocked
			if profileMissing {
				detail.Reason = session.AuthReasonNoPINProfile
			} else {
				detail.Reason = session.AuthReasonNoEnvelope
			}
			return detail, nil
		}
		detail.Status = session.KeyringUnavailable
		detail.Reason = session.AuthReasonKeyringUnavailable
		return detail, fmt.Errorf("app: load unlock envelope: %w", err)
	}
	detail.HasEnvelope = true

	// BootID dependency is required to validate the envelope.
	if s.deps.BootID == nil {
		detail.Status = session.LoggedInLocked
		detail.Reason = session.AuthReasonEnvelopeInvalid
		return detail, nil
	}

	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil {
		detail.Status = session.LoggedInLocked
		detail.Reason = session.AuthReasonEnvelopeInvalid
		return detail, fmt.Errorf("app: boot id: %w", err)
	}
	bootMatches = env.BootID == bootID
	envelopeExpired = !env.ExpiresAt.IsZero() && !s.now().Before(env.ExpiresAt)

	if err := env.Validate(ref, bootID, s.now()); err != nil {
		detail.Status = session.LoggedInLocked
		switch {
		case errors.Is(err, session.ErrBootChanged):
			detail.Reason = session.AuthReasonBootChanged
		case errors.Is(err, session.ErrPINBackoff):
			detail.Reason = session.AuthReasonPINBackoff
		case errors.Is(err, session.ErrAccountMismatch):
			detail.Reason = session.AuthReasonAccountMismatch
		default:
			detail.Reason = session.AuthReasonEnvelopeInvalid
		}
		return detail, nil
	}

	detail.EnvelopeValid = true
	detail.SoftUnlockAvailable = true
	detail.Status = session.LoggedInUnlockAvailable
	detail.Reason = session.AuthReasonSoftUnlockAvailable
	return detail, nil
}

// ---------------------------------------------------------------------------
// Mutation methods
// ---------------------------------------------------------------------------

// Create creates a new vault item. If remote is available, it tries to create
// online first. On failure or offline, it queues a pending mutation.
func (s *Service) Create(ctx context.Context, item vault.Item) (vault.Item, error) {
	return s.applyMutation(ctx, createMutation, mutation{Item: item})
}

// Update updates an existing vault item. Tries remote first, falls back to
// local pending mutation.
func (s *Service) Update(ctx context.Context, id string, item vault.Item) (vault.Item, error) {
	return s.applyMutation(ctx, updateMutation, mutation{ID: id, Item: item})
}

// Trash moves an item to the trash. Tries remote first, falls back to local pending.
func (s *Service) Trash(ctx context.Context, id string) error {
	_, err := s.applyMutation(ctx, trashMutation, mutation{ID: id})
	return err
}

// Restore restores an item from the trash. Tries remote first, falls back to local pending.
func (s *Service) Restore(ctx context.Context, id string) (vault.Item, error) {
	return s.applyMutation(ctx, restoreMutation, mutation{ID: id})
}

// Delete permanently deletes a vault item. Tries remote first, falls back to local pending.
func (s *Service) Delete(ctx context.Context, id string) error {
	_, err := s.applyMutation(ctx, deleteMutation, mutation{ID: id})
	return err
}

// ListAttachments is not yet supported.
func (s *Service) ListAttachments(ctx context.Context, itemID string) (attachments []vault.Attachment, retErr error) {
	log, started := logAppServiceStart(ctx, "attachment_list")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	return nil, cerrors.ErrUnsupported
}

// DownloadAttachment is not yet supported.
func (s *Service) DownloadAttachment(ctx context.Context, itemID, attachmentID string, dst io.Writer) (retErr error) {
	log, started := logAppServiceStart(ctx, "attachment_download")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	return cerrors.ErrUnsupported
}

// UploadAttachment is not yet supported.
func (s *Service) UploadAttachment(ctx context.Context, itemID, fileName string, size int64, src io.Reader) (attachment vault.Attachment, retErr error) {
	log, started := logAppServiceStart(ctx, "attachment_upload")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	return vault.Attachment{}, cerrors.ErrUnsupported
}

// DeleteAttachment is not yet supported.
func (s *Service) DeleteAttachment(ctx context.Context, itemID, attachmentID string) (retErr error) {
	log, started := logAppServiceStart(ctx, "attachment_delete")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	return cerrors.ErrUnsupported
}

// ResolveConflict resolves a sync conflict by applying the given resolution.
func (s *Service) ResolveConflict(ctx context.Context, conflictID string, resolution coresync.ConflictResolution) (retErr error) {
	log, started := logAppServiceStart(ctx, "conflict_resolve")
	defer func() {
		event := log.Info()
		msg := "app service operation finished"
		if retErr != nil {
			event = log.Error().Str("error_kind", safelog.SafeErrorKind(retErr))
			msg = "app service operation failed"
		}
		event.
			Str("resolution", string(resolution)).
			Int("count", 1).
			Int64(zerowrap.FieldDuration, time.Since(started).Milliseconds()).
			Msg(msg)
	}()

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	mode := s.sessionMode
	var key []byte
	if mode.cacheOnly() {
		key = append(key, s.cacheKey...)
	}
	s.mu.Unlock()

	if mode.cacheOnly() {
		defer clear(key)
		return s.resolveConflictCacheOnly(ctx, key, conflictID, resolution)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlocked(); err != nil {
		return err
	}

	// Find and remove the conflict.
	idx := -1
	for i, c := range s.conflicts {
		if c.ID == conflictID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return cerrors.ErrNotFound
	}
	conflict := s.conflicts[idx]
	s.conflicts = removeConflictsForItem(s.conflicts, conflict.ItemID)

	switch resolution {
	case coresync.ResolutionKeepRemote:
		// Replace local item with pending remote item if present, or remove
		// if remote missing.
		foundRemote := false
		for _, ritem := range s.pendingRemoteItems {
			if ritem.ID == conflict.ItemID {
				for i, item := range s.items {
					if item.ID == conflict.ItemID {
						ritem.SyncStatus = vault.SyncStatusSynced
						ritem.ConflictID = ""
						s.items[i] = ritem
						foundRemote = true
						break
					}
				}
				break
			}
		}
		if !foundRemote {
			// Remote item not found — it may have been deleted remotely.
			for i, item := range s.items {
				if item.ID == conflict.ItemID {
					s.items = append(s.items[:i], s.items[i+1:]...)
					break
				}
			}
		}
		s.outbox = removeOutboxMutationsForItem(s.outbox, conflict.ItemID)

	case coresync.ResolutionKeepLocal:
		// Keep existing outbox mutation(s), mark local item pending and clear ConflictID.
		for i, item := range s.items {
			if item.ID == conflict.ItemID {
				s.items[i].SyncStatus = vault.SyncStatusPending
				s.items[i].ConflictID = ""
				break
			}
		}
		remoteRevision := conflict.RemoteRevision
		if remoteRevision == "" {
			remoteRevision = revisionForItem(s.pendingRemoteItems, conflict.ItemID)
		}
		if remoteRevision != "" {
			setOutboxBaseRevisionForItem(s.outbox, conflict.ItemID, remoteRevision)
		}

	case coresync.ResolutionDuplicateLocal:
		// Clone the conflicting local item into a new pending create. The original
		// item is resolved to the remote version when available.
		var localCopy vault.Item
		originalIdx := -1
		for i, item := range s.items {
			if item.ID == conflict.ItemID {
				localCopy = item
				originalIdx = i
				break
			}
		}
		if originalIdx >= 0 {
			remoteInstalled := false
			for _, remoteItem := range s.pendingRemoteItems {
				if remoteItem.ID == conflict.ItemID {
					remoteItem.SyncStatus = vault.SyncStatusSynced
					remoteItem.ConflictID = ""
					s.items[originalIdx] = remoteItem
					remoteInstalled = true
					break
				}
			}
			if !remoteInstalled {
				s.items[originalIdx].SyncStatus = vault.SyncStatusSynced
				s.items[originalIdx].ConflictID = ""
			}

			dup := localCopy
			s.outboxSeq++
			now := s.now()
			dup.ID = fmt.Sprintf("local-%d-%d", now.UnixNano(), s.outboxSeq)
			dup.SyncStatus = vault.SyncStatusPending
			dup.ConflictID = ""
			s.items = append(s.items, dup)

			payload, err := json.Marshal(dup)
			if err != nil {
				return fmt.Errorf("app: marshal duplicate payload: %w", err)
			}
			s.outbox = append(s.outbox, coresync.OutboxMutation{
				ID:        fmt.Sprintf("m-%d-%d", now.UnixNano(), s.outboxSeq),
				Kind:      coresync.MutationCreate,
				ItemID:    dup.ID,
				CreatedAt: now,
				Payload:   payload,
			})

			// The original local mutation has been converted into a duplicate local
			// create, so remove mutations targeting the remote-resolved original.
			s.outbox = removeOutboxMutationsForItem(s.outbox, conflict.ItemID)
		}

	default:
		return cerrors.ErrUnsupported
	}

	s.rebuildIndexLocked()
	s.saveCacheAsyncLocked(ctx)
	remainingConflicts := len(s.conflicts)
	if remainingConflicts > 0 {
		s.emitCount(ConflictDetected, fmt.Sprintf("%d conflict(s) remaining", remainingConflicts), remainingConflicts)
	} else {
		s.emit(SyncUpdated, "conflict resolved")
	}
	return nil
}

func (s *Service) resolveConflictCacheOnly(ctx context.Context, key []byte, conflictID string, resolution coresync.ConflictResolution) error {
	if len(key) == 0 {
		return fmt.Errorf("app: conflict resolve: missing cache key")
	}

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	idx := -1
	for i, c := range s.conflicts {
		if c.ID == conflictID {
			idx = i
			break
		}
	}
	if idx == -1 {
		s.mu.Unlock()
		return cerrors.ErrNotFound
	}
	conflict := s.conflicts[idx]
	remainingConflicts := removeConflictsForItem(s.conflicts, conflict.ItemID)
	expectedSeq := s.saveSeq
	s.mu.Unlock()

	snap, err := s.vaultCache().Open(ctx, key)
	if err != nil {
		return err
	}
	if len(snap.Salt) == 0 {
		return fmt.Errorf("app: conflict resolve: no cache salt available")
	}
	snap.Items = append([]vault.Item(nil), snap.Items...)
	snap.Folders = append([]vault.Folder(nil), snap.Folders...)
	snap.Outbox = append([]coresync.OutboxMutation(nil), snap.Outbox...)
	snap.Conflicts = append([]coresync.Conflict(nil), remainingConflicts...)

	var remoteItems []vault.Item
	needsRemoteItems := resolution == coresync.ResolutionKeepRemote ||
		resolution == coresync.ResolutionDuplicateLocal ||
		(resolution == coresync.ResolutionKeepLocal && conflict.RemoteRevision == "")
	if needsRemoteItems {
		if s.deps.Remote == nil {
			return fmt.Errorf("app: conflict resolve: remote unavailable")
		}
		remoteItems, _, _, err = s.deps.Remote.Sync(ctx)
		if err != nil {
			return err
		}
	}

	switch resolution {
	case coresync.ResolutionKeepRemote:
		foundRemote := false
		for _, remoteItem := range remoteItems {
			if remoteItem.ID != conflict.ItemID {
				continue
			}
			remoteItem.SyncStatus = vault.SyncStatusSynced
			remoteItem.ConflictID = ""
			snap.Items = upsertVaultItem(snap.Items, remoteItem)
			foundRemote = true
			break
		}
		if !foundRemote {
			snap.Items = removeVaultItem(snap.Items, conflict.ItemID)
		}
		snap.Outbox = removeOutboxMutationsForItem(snap.Outbox, conflict.ItemID)

	case coresync.ResolutionKeepLocal:
		for i, item := range snap.Items {
			if item.ID == conflict.ItemID {
				snap.Items[i].SyncStatus = vault.SyncStatusPending
				snap.Items[i].ConflictID = ""
				break
			}
		}
		remoteRevision := conflict.RemoteRevision
		if remoteRevision == "" {
			remoteRevision = revisionForItem(remoteItems, conflict.ItemID)
		}
		if remoteRevision != "" {
			setOutboxBaseRevisionForItem(snap.Outbox, conflict.ItemID, remoteRevision)
		}

	case coresync.ResolutionDuplicateLocal:
		var localCopy vault.Item
		originalIdx := -1
		for i, item := range snap.Items {
			if item.ID == conflict.ItemID {
				localCopy = item
				originalIdx = i
				break
			}
		}
		if originalIdx >= 0 {
			remoteInstalled := false
			for _, remoteItem := range remoteItems {
				if remoteItem.ID != conflict.ItemID {
					continue
				}
				remoteItem.SyncStatus = vault.SyncStatusSynced
				remoteItem.ConflictID = ""
				snap.Items[originalIdx] = remoteItem
				remoteInstalled = true
				break
			}
			if !remoteInstalled {
				snap.Items[originalIdx].SyncStatus = vault.SyncStatusSynced
				snap.Items[originalIdx].ConflictID = ""
			}

			s.mu.Lock()
			s.outboxSeq++
			outboxSeq := s.outboxSeq
			s.mu.Unlock()
			now := s.now()

			dup := localCopy
			dup.ID = fmt.Sprintf("local-%d-%d", now.UnixNano(), outboxSeq)
			dup.SyncStatus = vault.SyncStatusPending
			dup.ConflictID = ""
			snap.Items = append(snap.Items, dup)

			payload, err := json.Marshal(dup)
			if err != nil {
				return fmt.Errorf("app: marshal duplicate payload: %w", err)
			}
			snap.Outbox = append(snap.Outbox, coresync.OutboxMutation{
				ID:        fmt.Sprintf("m-%d-%d", now.UnixNano(), outboxSeq),
				Kind:      coresync.MutationCreate,
				ItemID:    dup.ID,
				CreatedAt: now,
				Payload:   payload,
			})
			snap.Outbox = removeOutboxMutationsForItem(snap.Outbox, conflict.ItemID)
		}

	default:
		return cerrors.ErrUnsupported
	}

	if err := s.saveExplicitCacheSnapshot(ctx, key, snap, expectedSeq); err != nil {
		return err
	}

	s.mu.Lock()
	s.conflicts = removeConflictsForItem(s.conflicts, conflict.ItemID)
	remainingConflictCount := len(s.conflicts)
	s.pendingRemoteItems = nil
	s.pendingRemoteFolders = nil
	s.items = nil
	s.folders = nil
	s.outbox = nil
	s.index = nil
	s.mu.Unlock()

	if remainingConflictCount > 0 {
		s.emitCount(ConflictDetected, fmt.Sprintf("%d conflict(s) remaining", remainingConflictCount), remainingConflictCount)
	} else {
		s.emit(SyncUpdated, "conflict resolved")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

// replayOutbox replays outbox mutations against the remote. It must be called
// OUTSIDE of s.mu to avoid deadlocks with Remote methods.
func (s *Service) replayOutbox(ctx context.Context, outbox []coresync.OutboxMutation) (retErr error) {
	log, started := logAppServiceStart(ctx, "outbox_replay")
	defer func() { logAppServiceFinishCount(log, started, retErr, len(outbox)) }()

	if s.deps.Remote == nil {
		return nil
	}

	for _, m := range outbox {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := s.replayMutation(ctx, m); err != nil {
			return err
		}
	}

	return nil
}

// syncOnce performs a single sync cycle: checks remote revision, pushes local
// mutations, pulls remote changes, and detects conflicts.
func (s *Service) syncOnce(ctx context.Context) error {
	log, started := logAppServiceStart(ctx, "sync_once")
	var opErr error
	var count int
	defer func() { logAppServiceFinishCount(log, started, opErr, count) }()

	s.emit(SyncChecking, "checking remote revision")

	if s.deps.Remote == nil {
		return nil
	}

	rev, err := s.deps.Remote.Revision(ctx)
	if err != nil {
		opErr = err
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return err
	}

	// Snapshot the outbox under lock.
	s.mu.Lock()
	outboxSnapshot := make([]coresync.OutboxMutation, len(s.outbox))
	copy(outboxSnapshot, s.outbox)
	s.mu.Unlock()

	// If nothing to sync, return early.
	if len(outboxSnapshot) == 0 && rev == "" {
		s.emit(SyncUpdated, "already up to date")
		return nil
	}

	// Fetch remote changes.
	remoteItems, remoteFolders, remoteRev, err := s.deps.Remote.Sync(ctx)
	if err != nil {
		opErr = err
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return err
	}
	count = len(remoteItems) + len(remoteFolders) + len(outboxSnapshot)

	// Build remote change list for conflict detection.
	remoteChanges := make([]coresync.RemoteChange, 0, len(remoteItems))
	for _, ritem := range remoteItems {
		rc := coresync.RemoteChange{
			ItemID:   ritem.ID,
			Revision: ritem.RevisionDate.Format(time.RFC3339),
			Deleted:  ritem.Deleted,
		}
		remoteChanges = append(remoteChanges, rc)
	}

	s.mu.Lock()

	// Check context cancellation before proceeding.
	if ctx.Err() != nil {
		opErr = ctx.Err()
		s.mu.Unlock()
		return opErr
	}

	// Detect conflicts.
	conflicts := coresync.DetectConflicts(outboxSnapshot, remoteChanges)
	if len(conflicts) > 0 {
		log.Warn().
			Int("count", len(conflicts)).
			Msg("sync conflicts detected")
		// Store pending remote state for conflict resolution.
		s.pendingRemoteItems = make([]vault.Item, len(remoteItems))
		copy(s.pendingRemoteItems, remoteItems)
		s.pendingRemoteFolders = make([]vault.Folder, len(remoteFolders))
		copy(s.pendingRemoteFolders, remoteFolders)

		s.conflicts = replaceConflictsForItems(s.conflicts, conflicts)
		for _, c := range conflicts {
			for i, item := range s.items {
				if item.ID == c.ItemID {
					s.items[i].SyncStatus = vault.SyncStatusConflict
					s.items[i].ConflictID = c.ID
					break
				}
			}
		}
		s.rebuildIndexLocked()
		conflictCount := len(s.conflicts)
		s.mu.Unlock()
		s.emitCount(ConflictDetected, fmt.Sprintf("%d conflict(s) detected", conflictCount), conflictCount)
		return nil
	}

	s.mu.Unlock()

	// No conflicts: replay outbox before installing remote state.
	if len(outboxSnapshot) > 0 {
		if err := s.replayOutbox(ctx, outboxSnapshot); err != nil {
			opErr = err
			s.emit(SyncFailed, cerrors.ShortMessage(err))
			// Do NOT clear outbox or install remote state on replay failure.
			return err
		}

		// Re-fetch remote state after successful replay.
		remoteItems, remoteFolders, remoteRev, err = s.deps.Remote.Sync(ctx)
		if err != nil {
			opErr = err
			s.emit(SyncFailed, cerrors.ShortMessage(err))
			// Keep outbox intact.
			return err
		}
		count = len(remoteItems) + len(remoteFolders) + len(outboxSnapshot)
	}

	// Install final remote state under lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx.Err() != nil {
		opErr = ctx.Err()
		return opErr
	}

	s.items = remoteItems
	s.folders = remoteFolders
	for i := range s.items {
		s.items[i].SyncStatus = vault.SyncStatusSynced
	}
	if len(outboxSnapshot) > 0 {
		s.removeReplayedOutboxLocked(outboxSnapshot)
	}
	s.pendingRemoteItems = nil
	s.pendingRemoteFolders = nil
	s.rebuildIndexLocked()
	s.emit(SyncUpdated, fmt.Sprintf("sync complete (rev: %s)", remoteRev))

	// Persist cleared outbox.
	s.saveCacheAsyncLocked(ctx)
	return nil
}

// syncInterval returns the sync interval to use, falling back through
// Security.BackgroundSync.Interval, Sync.RevisionCheckInterval, then 5m.
func (s *Service) syncInterval() time.Duration {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	if cfg != nil && cfg.Security.BackgroundSync.Interval > 0 {
		return cfg.Security.BackgroundSync.Interval
	}
	if cfg != nil && cfg.Sync.RevisionCheckInterval > 0 {
		return cfg.Sync.RevisionCheckInterval
	}
	return 5 * time.Minute
}
