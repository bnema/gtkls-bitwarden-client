package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bnema/zerowrap"
	"golang.org/x/crypto/argon2"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/cache"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	cerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	safelog "github.com/bnema/gtk4-layershell-bitwarden/internal/core/logging"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
)

const (
	cacheKeyArgonTime    uint32 = 3
	cacheKeyArgonMemory  uint32 = 64 * 1024
	cacheKeyArgonThreads uint8  = 4
	cacheKeySize                = 32

	// minPINLength is the minimum number of characters required for a
	// local unlock PIN.
	minPINLength = 4
)

// deriveCacheKey derives the local encrypted-cache/outbox key from the master
// password and per-account salt. It intentionally does not log or persist the
// derived key.
func deriveCacheKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, cacheKeyArgonTime, cacheKeyArgonMemory, cacheKeyArgonThreads, cacheKeySize)
}

func newCacheSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

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
		event = log.Error().Str("error_kind", safelog.SafeErrorKind(err))
		msg = "app service operation failed"
	}
	event.Int64(zerowrap.FieldDuration, time.Since(started).Milliseconds()).Msg(msg)
}

func logAppServiceFinishCount(log zerowrap.Logger, started time.Time, err error, count int) {
	event := log.Info()
	msg := "app service operation finished"
	if err != nil {
		event = log.Error().Str("error_kind", safelog.SafeErrorKind(err))
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
	s.eventMu.RLock()
	closed := s.eventsClosed
	if !closed {
		select {
		case s.events <- Event{Kind: kind, Message: message}:
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

// Unlock transitions the service from locked to unlocked.
func (s *Service) Unlock(ctx context.Context, email, password string) (retErr error) {
	log, started := logAppServiceStart(ctx, "unlock")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	return s.unlock(ctx, email, password, nil)
}

// UnlockWithTwoFactor transitions the service from locked to unlocked, prompting
// for a two-factor code when the remote requires it.
func (s *Service) UnlockWithTwoFactor(ctx context.Context, email, password string, prompt auth.TwoFactorPrompt) error {
	return s.unlock(ctx, email, password, prompt)
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lifecycle != token || s.state != auth.LockStateUnlocking {
		return fmt.Errorf("app: unlock lifecycle superseded: %w", context.Canceled)
	}

	// Copy cache key from material (derived during Login).
	s.zeroCacheKeyLocked()
	s.cacheKey = make([]byte, len(material.CacheKey))
	copy(s.cacheKey, material.CacheKey)
	s.state = auth.LockStateUnlocked

	// PIN unlock intentionally avoids background sync to prevent resident
	// vault plaintext (s.items/s.folders) in memory for the session lifetime.
	// Sync can be added later with operation-scoped persistence that does not
	// pin plaintext to the resident Service state.
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

// UnlockAndCreateEnvelope unlocks with master password, exports session
// material, creates a PIN envelope, and installs local state. It provides a
// safe path for the GUI to transition from LoggedInLocked to fully enrolled
// without requiring a CLI login. Returns an error if PIN envelope
// dependencies are unavailable.
func (s *Service) UnlockAndCreateEnvelope(ctx context.Context, email, password, pin string, prompt auth.TwoFactorPrompt) (retErr error) {
	log, started := logAppServiceStart(ctx, "unlock_create_envelope")
	defer func() { logAppServiceFinish(log, started, retErr) }()

	if s.deps.PINEnvelope == nil {
		return fmt.Errorf("app: unlock-enroll: %w", cerrors.ErrUnsupported)
	}
	if s.deps.Credentials == nil {
		return fmt.Errorf("app: unlock-enroll: %w", cerrors.ErrUnsupported)
	}
	if s.deps.BootID == nil {
		return fmt.Errorf("app: unlock-enroll: %w", cerrors.ErrUnsupported)
	}
	if err := s.checkCredentialsAvailable(ctx); err != nil {
		return fmt.Errorf("app: unlock-enroll: credentials: %w", err)
	}

	// Validate PIN before any remote login.
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return fmt.Errorf("app: unlock-enroll: PIN is required")
	}
	if len(pin) < minPINLength {
		return fmt.Errorf("app: unlock-enroll: PIN must be at least %d characters", minPINLength)
	}

	// Perform remote login.
	if err := s.unlock(ctx, email, password, prompt); err != nil {
		return err
	}

	// Ensure local unlocked state/plaintext is cleared on any error after unlock.
	// Detach from cancellation while preserving logger values for cleanup.
	defer func() {
		if retErr != nil {
			_ = s.Lock(context.WithoutCancel(ctx))
		}
	}()

	// Export session material.
	material, tokens, err := s.deps.Remote.ExportSession(ctx)
	if err != nil {
		return fmt.Errorf("app: export session: %w", err)
	}
	defer material.Close()
	defer tokens.Close()

	// Read cache key from service under lock.
	s.mu.Lock()
	var cacheKey []byte
	if len(s.cacheKey) > 0 {
		cacheKey = make([]byte, len(s.cacheKey))
		copy(cacheKey, s.cacheKey)
	}
	s.mu.Unlock()

	unlockMaterial := material.Clone()
	defer unlockMaterial.Close()
	if len(cacheKey) > 0 {
		unlockMaterial.CacheKey = cacheKey
	}

	ref := s.accountRef(email)
	tokens.Email = ref.Email
	tokens.ServerURL = ref.ServerURL
	tokens.UpdatedAt = s.now()

	// Create PIN profile with verifier hash and random envelope key.
	profile, err := session.NewPINProfile(ref, tokens.AccountID, pin, s.now())
	if err != nil {
		return fmt.Errorf("app: create pin profile: %w", err)
	}
	defer profile.Close()

	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil {
		return fmt.Errorf("app: boot id: %w", err)
	}

	// Create envelope using the profile's high-entropy EnvelopeKey.
	envSecret := envelopeKeyToSecret(profile.EnvelopeKey)
	envelope, err := s.deps.PINEnvelope.Create(ctx, ref, unlockMaterial, envSecret, bootID)
	if err != nil {
		return fmt.Errorf("app: create envelope: %w", err)
	}
	if tokens.AccountID != "" {
		envelope.AccountID = tokens.AccountID
	}

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
		_ = s.deps.Credentials.DeleteTokenBundle(ctx, ref)
		_ = s.deps.Credentials.DeletePINProfile(ctx, ref)
		envelope.Close()
		return fmt.Errorf("app: save unlock envelope: %w", err)
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
		if prompt != nil {
			challenge, err := s.deps.Remote.BeginLogin(ctx, email, password)
			if err != nil {
				s.mu.Lock()
				s.state = auth.LockStateLocked
				s.mu.Unlock()
				return fmt.Errorf("app: login failed: %w", err)
			}
			if challenge != nil {
				defer challenge.Close()
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
		} else if err := s.deps.Remote.Login(ctx, email, password); err != nil {
			s.mu.Lock()
			s.state = auth.LockStateLocked
			s.mu.Unlock()
			return fmt.Errorf("app: login failed: %w", err)
		}
	}

	// Load cache data: derives key via Argon2id using salt from the encrypted
	// snapshot or a fresh random salt for first-run/no-cache flows.
	loadedItems, loadedFolders, outboxMutations, cacheKey, cacheSalt, loaded, err := s.loadCacheData(ctx, password)
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
	defer s.mu.Unlock()

	if s.lifecycle != token || s.state != auth.LockStateUnlocking {
		// Another Lock/Unlock cycle happened, do not install.
		return fmt.Errorf("app: unlock lifecycle superseded: %w", context.Canceled)
	}

	// Install cache data.
	if loaded {
		s.items = loadedItems
		s.folders = loadedFolders
		s.outbox = outboxMutations
	}
	// Copy cache key for outbox persistence.
	s.cacheKey = make([]byte, len(cacheKey))
	copy(s.cacheKey, cacheKey)
	s.cacheSalt = append(s.cacheSalt[:0], cacheSalt...)
	s.state = auth.LockStateUnlocked

	if loaded {
		s.emit(IndexReady, "search index ready")
	}

	// Start background sync worker detached from cancellation while preserving logger values.
	workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.cancelWorkers = cancel
	s.emit(Unlocking, "starting sync worker")

	s.startMinimalSyncWorker(workerCtx)

	return nil
}

// loadCacheData loads and decrypts a cached vault snapshot, returning the
// items, folders, outbox mutations, derived cache key, salt, and whether
// data was loaded. It does NOT install state on the service.
func (s *Service) loadCacheData(ctx context.Context, password string) (items []vault.Item, folders []vault.Folder, outbox []coresync.OutboxMutation, key []byte, salt []byte, loaded bool, err error) {
	log, started := logAppServiceStart(ctx, "cache_load_data")
	defer func() {
		logAppServiceFinishCount(log, started, err, len(items)+len(folders)+len(outbox))
	}()

	salt, err = newCacheSalt()
	if err != nil {
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache salt: %w", err)
	}
	key = deriveCacheKey(password, salt)

	if s.deps.Cache == nil {
		return nil, nil, nil, key, salt, false, nil
	}

	snap, snapErr := s.deps.Cache.Load(ctx)
	if snapErr != nil {
		if errors.Is(snapErr, os.ErrNotExist) {
			return nil, nil, nil, key, salt, false, nil
		}
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache load: %w", snapErr)
	}

	if snap.Version == 0 && snap.AccountHash == "" && len(snap.VaultCiphertext) == 0 {
		return nil, nil, nil, key, salt, false, nil
	}

	if err := cache.ValidateSnapshot(snap); err != nil {
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache validation: %w", err)
	}

	// Prefer the persisted random salt from the encrypted cache snapshot. Fresh
	// first-run/no-cache salts are persisted with the next encrypted cache save.
	if len(snap.CacheKeySalt) > 0 {
		salt = append([]byte(nil), snap.CacheKeySalt...)
		key = deriveCacheKey(password, salt)
	}

	var plaintext []byte
	if s.deps.SecretBox != nil {
		plaintext, err = s.deps.SecretBox.Open(snap.VaultCiphertext, key)
		if err != nil {
			return nil, nil, nil, nil, nil, false, fmt.Errorf("cache decrypt: %w", err)
		}
	} else {
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache decrypt: secretbox unavailable")
	}

	// Zero plaintext bytes on any return path after SecretBox.Open succeeds,
	// including early decode errors.
	defer clear(plaintext)

	var plain cache.PlainSnapshot
	if err := json.Unmarshal(plaintext, &plain); err != nil {
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache decode: %w", err)
	}
	defer func() {
		clear(plain.ItemsJSON)
		clear(plain.FoldersJSON)
		clear(plain.OutboxJSON)
	}()

	if err := json.Unmarshal(plain.ItemsJSON, &items); err != nil {
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache items decode: %w", err)
	}

	if err := json.Unmarshal(plain.FoldersJSON, &folders); err != nil {
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache folders decode: %w", err)
	}

	// Decode outbox from PlainSnapshot.OutboxJSON.
	if len(plain.OutboxJSON) > 0 {
		var cachedOutbox []coresync.OutboxMutation
		if err := json.Unmarshal(plain.OutboxJSON, &cachedOutbox); err != nil {
			return nil, nil, nil, nil, nil, false, fmt.Errorf("cache outbox decode: %w", err)
		}
		outbox = cachedOutbox
	}

	// Load outbox from deps.Outbox if available.
	if s.deps.Outbox != nil {
		storedMutations, loadErr := s.deps.Outbox.Load(ctx, key)
		if loadErr == nil && len(storedMutations) > 0 {
			outbox = append(outbox, storedMutations...)
		}
		if loadErr != nil {
			log.Warn().
				Str(zerowrap.FieldOperation, "outbox_load_data").
				Str("error_kind", safelog.SafeErrorKind(loadErr)).
				Msg("outbox load skipped")
		}
	}

	// Deduplicate outbox mutations by ID, preserving first occurrence.
	seen := make(map[string]struct{}, len(outbox))
	deduped := outbox[:0]
	for _, m := range outbox {
		if _, ok := seen[m.ID]; ok {
			continue
		}
		seen[m.ID] = struct{}{}
		deduped = append(deduped, m)
	}
	outbox = deduped

	return items, folders, outbox, key, salt, true, nil
}

// loadCachedVaultWithKey loads and decrypts the cache snapshot using the
// provided key (typically s.cacheKey from a PIN unlock envelope), returning
// items, folders, and outbox mutations. It zeros plaintext buffers after
// decode and does not install any state on the service. If the cache is
// missing, empty, or unavailable, nil slices and nil error are returned.
func (s *Service) loadCachedVaultWithKey(ctx context.Context, key []byte) (items []vault.Item, folders []vault.Folder, outbox []coresync.OutboxMutation, retErr error) {
	log, started := logAppServiceStart(ctx, "cache_load_with_material")
	defer func() { logAppServiceFinishCount(log, started, retErr, len(items)+len(folders)+len(outbox)) }()

	if s.deps.Cache == nil || s.deps.SecretBox == nil {
		return nil, nil, nil, nil
	}
	if len(key) == 0 {
		return nil, nil, nil, nil
	}

	snap, err := s.deps.Cache.Load(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, fmt.Errorf("cache load: %w", err)
	}

	// Empty snapshot: no data to return.
	if snap.Version == 0 && snap.AccountHash == "" && len(snap.VaultCiphertext) == 0 {
		return nil, nil, nil, nil
	}

	if err := cache.ValidateSnapshot(snap); err != nil {
		return nil, nil, nil, fmt.Errorf("cache validation: %w", err)
	}

	plaintext, err := s.deps.SecretBox.Open(snap.VaultCiphertext, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cache decrypt: %w", err)
	}
	defer clear(plaintext)

	var plain cache.PlainSnapshot
	if err := json.Unmarshal(plaintext, &plain); err != nil {
		return nil, nil, nil, fmt.Errorf("cache decode: %w", err)
	}
	defer func() {
		clear(plain.ItemsJSON)
		clear(plain.FoldersJSON)
		clear(plain.OutboxJSON)
	}()

	if err := json.Unmarshal(plain.ItemsJSON, &items); err != nil {
		return nil, nil, nil, fmt.Errorf("cache items decode: %w", err)
	}

	if err := json.Unmarshal(plain.FoldersJSON, &folders); err != nil {
		return nil, nil, nil, fmt.Errorf("cache folders decode: %w", err)
	}

	if len(plain.OutboxJSON) > 0 {
		if err := json.Unmarshal(plain.OutboxJSON, &outbox); err != nil {
			return nil, nil, nil, fmt.Errorf("cache outbox decode: %w", err)
		}
	}

	return items, folders, outbox, nil
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
// Items are loaded from the encrypted cache when available, or from resident
// state as a fallback. A local search index is built for the query and
// discarded afterward; no resident index is consulted or modified.
func (s *Service) Search(ctx context.Context, query string, limit int) ([]vault.ScoredItem, error) {
	s.mu.Lock()
	if s.state != auth.LockStateUnlocked {
		s.mu.Unlock()
		return nil, cerrors.ErrLocked
	}
	// Copy cache key and fallback items under lock, then release.
	cacheKey := make([]byte, len(s.cacheKey))
	copy(cacheKey, s.cacheKey)
	residentItems := make([]vault.Item, len(s.items))
	copy(residentItems, s.items)
	s.mu.Unlock()

	var items []vault.Item
	if len(cacheKey) > 0 {
		if loaded, _, _, err := s.loadCachedVaultWithKey(ctx, cacheKey); err == nil && len(loaded) > 0 {
			items = loaded
		}
	}
	if items == nil {
		items = residentItems
	}

	if len(items) == 0 {
		return nil, nil
	}

	// Build a local index scoped to this call; do not install on Service.
	idx := vault.BuildIndex(items)
	return idx.Search(query, limit), nil
}

// Items returns a copy of all vault items. Returns ErrLocked if not unlocked.
// Items are loaded from the encrypted cache when available, or from resident
// state as a fallback.
func (s *Service) Items(ctx context.Context) ([]vault.Item, error) {
	s.mu.Lock()
	if s.state != auth.LockStateUnlocked {
		s.mu.Unlock()
		return nil, cerrors.ErrLocked
	}
	// Copy cache key and fallback items under lock, then release.
	cacheKey := make([]byte, len(s.cacheKey))
	copy(cacheKey, s.cacheKey)
	residentItems := make([]vault.Item, len(s.items))
	copy(residentItems, s.items)
	s.mu.Unlock()

	var items []vault.Item
	if len(cacheKey) > 0 {
		if loaded, _, _, err := s.loadCachedVaultWithKey(ctx, cacheKey); err == nil && len(loaded) > 0 {
			items = loaded
		}
	}
	if items == nil {
		items = residentItems
	}

	result := make([]vault.Item, len(items))
	copy(result, items)
	return result, nil
}

// Get returns a single vault item by ID. Items are loaded from the encrypted
// cache when available, or from resident state as a fallback. Returns
// ErrNotFound when the item is not found.
func (s *Service) Get(ctx context.Context, id string) (vault.Item, error) {
	s.mu.Lock()
	if s.state != auth.LockStateUnlocked {
		s.mu.Unlock()
		return vault.Item{}, cerrors.ErrLocked
	}
	// Copy cache key and fallback items under lock, then release.
	cacheKey := make([]byte, len(s.cacheKey))
	copy(cacheKey, s.cacheKey)
	residentItems := make([]vault.Item, len(s.items))
	copy(residentItems, s.items)
	s.mu.Unlock()

	var items []vault.Item
	if len(cacheKey) > 0 {
		if loaded, _, _, err := s.loadCachedVaultWithKey(ctx, cacheKey); err == nil && len(loaded) > 0 {
			items = loaded
		}
	}
	if items == nil {
		items = residentItems
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

// appendOutboxLocked appends a mutation to the outbox and returns it.
// The caller must hold s.mu.
func (s *Service) appendOutboxLocked(ctx context.Context, kind coresync.MutationKind, itemID string, payload []byte) coresync.OutboxMutation {
	s.outboxSeq++
	m := coresync.OutboxMutation{
		ID:        fmt.Sprintf("m-%d-%d", s.now().UnixNano(), s.outboxSeq),
		Kind:      kind,
		ItemID:    itemID,
		CreatedAt: s.now(),
		Payload:   payload,
	}
	s.outbox = append(s.outbox, m)
	s.saveCacheAsyncLocked(ctx)
	return m
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
	outboxStore := s.deps.Outbox
	cacheStore := s.deps.Cache
	box := s.deps.SecretBox
	accountHash := s.accountHashLocked()

	if len(key) == 0 {
		return
	}

	s.saveWG.Add(1)
	go func() {
		defer s.saveWG.Done()
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		if outboxStore != nil {
			outboxLog, outboxStarted := logAppServiceStart(cleanupCtx, "save_outbox")
			err := outboxStore.Save(cleanupCtx, key, outboxSnap)
			logAppServiceFinishCount(outboxLog, outboxStarted, err, len(outboxSnap))
		}

		if cacheStore != nil && box != nil && len(salt) > 0 {
			cacheLog, cacheStarted := logAppServiceStart(cleanupCtx, "save_cache")
			err := saveEncryptedSnapshot(cleanupCtx, cacheStore, box, key, salt, accountHash, itemsSnap, foldersSnap, outboxSnap)
			logAppServiceFinishCount(cacheLog, cacheStarted, err, len(itemsSnap)+len(foldersSnap)+len(outboxSnap))
		}
	}()
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
		case errors.Is(err, session.ErrUnlockExpired):
			detail.Reason = session.AuthReasonEnvelopeExpired
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

func saveEncryptedSnapshot(ctx context.Context, store interface {
	Save(context.Context, cache.Snapshot) error
}, box interface {
	Seal([]byte, []byte) ([]byte, error)
}, key, salt []byte, accountHash string, items []vault.Item, folders []vault.Folder, outbox []coresync.OutboxMutation) error {
	itemsJSON, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("cache marshal items: %w", err)
	}
	foldersJSON, err := json.Marshal(folders)
	if err != nil {
		return fmt.Errorf("cache marshal folders: %w", err)
	}
	outboxJSON, err := json.Marshal(outbox)
	if err != nil {
		return fmt.Errorf("cache marshal outbox: %w", err)
	}

	plain := cache.PlainSnapshot{
		AccountHash:  accountHash,
		SavedAt:      time.Now().UTC(),
		CacheKeySalt: salt,
		ItemsJSON:    itemsJSON,
		FoldersJSON:  foldersJSON,
		OutboxJSON:   outboxJSON,
	}
	plainJSON, err := json.Marshal(plain)
	if err != nil {
		return fmt.Errorf("cache marshal snapshot: %w", err)
	}
	ciphertext, err := box.Seal(plainJSON, key)
	if err != nil {
		return fmt.Errorf("cache encrypt: %w", err)
	}

	return store.Save(ctx, cache.Snapshot{
		Version:         cache.Version,
		AccountHash:     accountHash,
		SavedAt:         plain.SavedAt,
		CacheKeySalt:    append([]byte(nil), salt...),
		VaultCiphertext: ciphertext,
	})
}

// ---------------------------------------------------------------------------
// Mutation methods
// ---------------------------------------------------------------------------

// Create creates a new vault item. If remote is available, it tries to create
// online first. On failure or offline, it queues a pending mutation.
func (s *Service) Create(ctx context.Context, item vault.Item) (retItem vault.Item, retErr error) {
	log, started := logAppServiceStart(ctx, "mutation_create")
	defer func() {
		count := 0
		if retErr == nil && retItem.ID != "" {
			count = 1
		}
		logAppServiceFinishCount(log, started, retErr, count)
	}()

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return vault.Item{}, err
	}
	s.mu.Unlock()

	// Try remote if available.
	if s.deps.Remote != nil {
		remoteItem, err := s.deps.Remote.Create(ctx, item)
		if err == nil {
			s.mu.Lock()
			if err := s.ensureUnlocked(); err != nil {
				s.mu.Unlock()
				logRemoteSuccessLocalLocked(ctx, "remote_create_local_update")
				return vault.Item{}, err
			}
			remoteItem.SyncStatus = vault.SyncStatusSynced
			s.items = append(s.items, remoteItem)
			s.rebuildIndexLocked()
			s.mu.Unlock()
			s.emit(SyncUpdated, "item created remotely")
			return remoteItem, nil
		}
	}

	// Remote missing or error: queue pending locally.
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureUnlocked(); err != nil {
		return vault.Item{}, err
	}

	if item.ID == "" {
		s.outboxSeq++
		item.ID = fmt.Sprintf("local-%d-%d", s.now().UnixNano(), s.outboxSeq)
	}
	item.SyncStatus = vault.SyncStatusPending
	item.RevisionDate = s.now()

	payload, err := json.Marshal(item)
	if err != nil {
		return vault.Item{}, fmt.Errorf("app: marshal create payload: %w", err)
	}
	s.appendOutboxLocked(ctx, coresync.MutationCreate, item.ID, payload)

	s.items = append(s.items, item)
	s.rebuildIndexLocked()
	s.emit(MutationPending, "item queued for creation")
	return item, nil
}

// Update updates an existing vault item. Tries remote first, falls back to
// local pending mutation.
func (s *Service) Update(ctx context.Context, id string, item vault.Item) (retItem vault.Item, retErr error) {
	log, started := logAppServiceStart(ctx, "mutation_update")
	defer func() {
		count := 0
		if retErr == nil && retItem.ID != "" {
			count = 1
		}
		logAppServiceFinishCount(log, started, retErr, count)
	}()

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return vault.Item{}, err
	}
	s.mu.Unlock()

	if s.deps.Remote != nil {
		remoteItem, err := s.deps.Remote.Update(ctx, id, item)
		if err == nil {
			s.mu.Lock()
			if err := s.ensureUnlocked(); err != nil {
				s.mu.Unlock()
				logRemoteSuccessLocalLocked(ctx, "remote_update_local_update")
				return vault.Item{}, err
			}
			remoteItem.SyncStatus = vault.SyncStatusSynced
			for i, existing := range s.items {
				if existing.ID == id {
					s.items[i] = remoteItem
					break
				}
			}
			s.rebuildIndexLocked()
			s.mu.Unlock()
			s.emit(SyncUpdated, "item updated remotely")
			return remoteItem, nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureUnlocked(); err != nil {
		return vault.Item{}, err
	}

	item.ID = id
	item.SyncStatus = vault.SyncStatusPending
	item.RevisionDate = s.now()

	payload, err := json.Marshal(item)
	if err != nil {
		return vault.Item{}, fmt.Errorf("app: marshal update payload: %w", err)
	}
	s.appendOutboxLocked(ctx, coresync.MutationUpdate, id, payload)

	found := false
	for i, existing := range s.items {
		if existing.ID == id {
			s.items[i] = item
			found = true
			break
		}
	}
	if !found {
		s.items = append(s.items, item)
	}
	s.rebuildIndexLocked()
	s.emit(MutationPending, "item queued for update")
	return item, nil
}

// Trash moves an item to the trash. Tries remote first, falls back to local pending.
func (s *Service) Trash(ctx context.Context, id string) (retErr error) {
	log, started := logAppServiceStart(ctx, "mutation_trash")
	defer func() {
		count := 0
		if retErr == nil {
			count = 1
		}
		logAppServiceFinishCount(log, started, retErr, count)
	}()

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	if s.deps.Remote != nil {
		err := s.deps.Remote.Trash(ctx, id)
		if err == nil {
			s.mu.Lock()
			if err := s.ensureUnlocked(); err != nil {
				s.mu.Unlock()
				logRemoteSuccessLocalLocked(ctx, "remote_trash_local_update")
				return err
			}
			for i, existing := range s.items {
				if existing.ID == id {
					s.items[i].Deleted = true
					s.items[i].SyncStatus = vault.SyncStatusSynced
					break
				}
			}
			s.rebuildIndexLocked()
			s.mu.Unlock()
			s.emit(SyncUpdated, "item trashed remotely")
			return nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureUnlocked(); err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]string{"id": id})
	if err != nil {
		return fmt.Errorf("app: marshal trash payload: %w", err)
	}
	s.appendOutboxLocked(ctx, coresync.MutationTrash, id, payload)

	for i, existing := range s.items {
		if existing.ID == id {
			s.items[i].Deleted = true
			s.items[i].SyncStatus = vault.SyncStatusPending
			break
		}
	}

	s.rebuildIndexLocked()
	s.emit(MutationPending, "item queued for trash")
	return nil
}

// Restore restores an item from the trash. Tries remote first, falls back to local pending.
func (s *Service) Restore(ctx context.Context, id string) (retItem vault.Item, retErr error) {
	log, started := logAppServiceStart(ctx, "mutation_restore")
	defer func() {
		count := 0
		if retErr == nil && retItem.ID != "" {
			count = 1
		}
		logAppServiceFinishCount(log, started, retErr, count)
	}()

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return vault.Item{}, err
	}
	s.mu.Unlock()

	if s.deps.Remote != nil {
		remoteItem, err := s.deps.Remote.Restore(ctx, id)
		if err == nil {
			s.mu.Lock()
			if err := s.ensureUnlocked(); err != nil {
				s.mu.Unlock()
				logRemoteSuccessLocalLocked(ctx, "remote_restore_local_update")
				return vault.Item{}, err
			}
			remoteItem.Deleted = false
			remoteItem.SyncStatus = vault.SyncStatusSynced
			for i, existing := range s.items {
				if existing.ID == id {
					s.items[i] = remoteItem
					break
				}
			}
			s.rebuildIndexLocked()
			s.mu.Unlock()
			s.emit(SyncUpdated, "item restored remotely")
			return remoteItem, nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureUnlocked(); err != nil {
		return vault.Item{}, err
	}

	payload, err := json.Marshal(map[string]string{"id": id})
	if err != nil {
		return vault.Item{}, fmt.Errorf("app: marshal restore payload: %w", err)
	}
	s.appendOutboxLocked(ctx, coresync.MutationRestore, id, payload)

	var restored vault.Item
	for i, existing := range s.items {
		if existing.ID == id {
			s.items[i].Deleted = false
			s.items[i].SyncStatus = vault.SyncStatusPending
			restored = s.items[i]
			break
		}
	}

	s.rebuildIndexLocked()
	s.emit(MutationPending, "item queued for restore")
	return restored, nil
}

// Delete permanently deletes a vault item. Tries remote first, falls back to local pending.
func (s *Service) Delete(ctx context.Context, id string) (retErr error) {
	log, started := logAppServiceStart(ctx, "mutation_delete")
	defer func() {
		count := 0
		if retErr == nil {
			count = 1
		}
		logAppServiceFinishCount(log, started, retErr, count)
	}()

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	if s.deps.Remote != nil {
		err := s.deps.Remote.Delete(ctx, id)
		if err == nil {
			s.mu.Lock()
			if err := s.ensureUnlocked(); err != nil {
				s.mu.Unlock()
				logRemoteSuccessLocalLocked(ctx, "remote_delete_local_update")
				return err
			}
			for i, existing := range s.items {
				if existing.ID == id {
					s.items = append(s.items[:i], s.items[i+1:]...)
					break
				}
			}
			s.rebuildIndexLocked()
			s.mu.Unlock()
			s.emit(SyncUpdated, "item deleted remotely")
			return nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureUnlocked(); err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]string{"id": id})
	if err != nil {
		return fmt.Errorf("app: marshal delete payload: %w", err)
	}
	s.appendOutboxLocked(ctx, coresync.MutationDelete, id, payload)

	for i, existing := range s.items {
		if existing.ID == id {
			s.items = append(s.items[:i], s.items[i+1:]...)
			break
		}
	}

	s.rebuildIndexLocked()
	s.emit(MutationPending, "item queued for deletion")
	return nil
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
	s.conflicts = append(s.conflicts[:idx], s.conflicts[idx+1:]...)

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
		// Remove outbox mutations for this item.
		var kept []coresync.OutboxMutation
		for _, m := range s.outbox {
			if m.ItemID != conflict.ItemID {
				kept = append(kept, m)
			}
		}
		s.outbox = kept

	case coresync.ResolutionKeepLocal:
		// Keep existing outbox mutation(s), mark local item pending and clear ConflictID.
		for i, item := range s.items {
			if item.ID == conflict.ItemID {
				s.items[i].SyncStatus = vault.SyncStatusPending
				s.items[i].ConflictID = ""
				break
			}
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
			dup.ID = fmt.Sprintf("local-%d-%d", s.now().UnixNano(), s.outboxSeq)
			dup.SyncStatus = vault.SyncStatusPending
			dup.ConflictID = ""
			s.items = append(s.items, dup)

			payload, err := json.Marshal(dup)
			if err != nil {
				return fmt.Errorf("app: marshal duplicate payload: %w", err)
			}
			s.outbox = append(s.outbox, coresync.OutboxMutation{
				ID:        fmt.Sprintf("m-%d-%d", s.now().UnixNano(), s.outboxSeq),
				Kind:      coresync.MutationCreate,
				ItemID:    dup.ID,
				CreatedAt: s.now(),
				Payload:   payload,
			})

			// The original local mutation has been converted into a duplicate local
			// create, so remove mutations targeting the remote-resolved original.
			kept := s.outbox[:0]
			for _, mutation := range s.outbox {
				if mutation.ItemID != conflict.ItemID {
					kept = append(kept, mutation)
				}
			}
			s.outbox = kept
		}
	}

	s.rebuildIndexLocked()
	s.saveCacheAsyncLocked(ctx)
	s.emit(SyncUpdated, "conflict resolved")
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

		switch m.Kind {
		case coresync.MutationCreate, coresync.MutationUpdate:
			var item vault.Item
			if err := json.Unmarshal(m.Payload, &item); err != nil {
				return fmt.Errorf("replay unmarshal: %w", err)
			}
			var err error
			if m.Kind == coresync.MutationCreate {
				_, err = s.deps.Remote.Create(ctx, item)
			} else {
				_, err = s.deps.Remote.Update(ctx, m.ItemID, item)
			}
			if err != nil {
				return fmt.Errorf("replay %s: %w", m.Kind, err)
			}

		case coresync.MutationTrash:
			if err := s.deps.Remote.Trash(ctx, m.ItemID); err != nil {
				return fmt.Errorf("replay trash: %w", err)
			}

		case coresync.MutationRestore:
			if _, err := s.deps.Remote.Restore(ctx, m.ItemID); err != nil {
				return fmt.Errorf("replay restore: %w", err)
			}

		case coresync.MutationDelete:
			if err := s.deps.Remote.Delete(ctx, m.ItemID); err != nil {
				return fmt.Errorf("replay delete: %w", err)
			}

		default:
			return fmt.Errorf("%w: unknown mutation kind %s", cerrors.ErrUnsupported, m.Kind)
		}
	}

	return nil
}

// syncOnce performs a single sync cycle: checks remote revision, pushes local
// mutations, pulls remote changes, and detects conflicts.
func (s *Service) syncOnce(ctx context.Context) {
	log, started := logAppServiceStart(ctx, "sync_once")
	var opErr error
	var count int
	defer func() { logAppServiceFinishCount(log, started, opErr, count) }()

	s.emit(SyncChecking, "checking remote revision")

	if s.deps.Remote == nil {
		return
	}

	rev, err := s.deps.Remote.Revision(ctx)
	if err != nil {
		opErr = err
		s.emit(SyncFailed, fmt.Sprintf("revision check failed: %v", err))
		return
	}

	// Snapshot the outbox under lock.
	s.mu.Lock()
	outboxSnapshot := make([]coresync.OutboxMutation, len(s.outbox))
	copy(outboxSnapshot, s.outbox)
	s.mu.Unlock()

	// If nothing to sync, return early.
	if len(outboxSnapshot) == 0 && rev == "" {
		s.emit(SyncUpdated, "already up to date")
		return
	}

	// Fetch remote changes.
	remoteItems, remoteFolders, remoteRev, err := s.deps.Remote.Sync(ctx)
	if err != nil {
		opErr = err
		s.emit(SyncFailed, fmt.Sprintf("remote sync failed: %v", err))
		return
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
		return
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

		s.conflicts = append(s.conflicts, conflicts...)
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
		s.mu.Unlock()
		s.emit(ConflictDetected, fmt.Sprintf("%d conflict(s) detected", len(conflicts)))
		return
	}

	s.mu.Unlock()

	// No conflicts: replay outbox before installing remote state.
	if len(outboxSnapshot) > 0 {
		if err := s.replayOutbox(ctx, outboxSnapshot); err != nil {
			opErr = err
			s.emit(SyncFailed, fmt.Sprintf("outbox replay failed: %v", err))
			// Do NOT clear outbox or install remote state on replay failure.
			return
		}

		// Re-fetch remote state after successful replay.
		remoteItems, remoteFolders, remoteRev, err = s.deps.Remote.Sync(ctx)
		if err != nil {
			opErr = err
			s.emit(SyncFailed, fmt.Sprintf("post-replay sync failed: %v", err))
			// Keep outbox intact.
			return
		}
		count = len(remoteItems) + len(remoteFolders) + len(outboxSnapshot)
	}

	// Install final remote state under lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx.Err() != nil {
		opErr = ctx.Err()
		return
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

// startMinimalSyncWorker starts a background goroutine that runs an initial
// sync, then periodic syncs at the configured interval until ctx is done.
func (s *Service) startMinimalSyncWorker(ctx context.Context) {
	go func() {
		// Run initial sync immediately.
		s.syncOnce(ctx)

		// Then run periodic syncs.
		ticker := time.NewTicker(s.syncInterval())
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.syncOnce(ctx)
			}
		}
	}()
}
