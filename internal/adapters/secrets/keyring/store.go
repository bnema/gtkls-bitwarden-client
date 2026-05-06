package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bnema/zerowrap"
	zaladokeyring "github.com/zalando/go-keyring"

	coreerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	safelog "github.com/bnema/gtk4-layershell-bitwarden/internal/core/logging"
	session "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
)

// Service names and probe user for the OS keyring.
const (
	serviceToken      = "gtk4-layershell-bitwarden/token"
	serviceUnlock     = "gtk4-layershell-bitwarden/unlock"
	servicePINProfile = "gtk4-layershell-bitwarden/pin-profile"
	serviceProbe      = "gtk4-layershell-bitwarden/probe"
	probeUser         = "availability"
	probeValue        = "ok"
)

// errNotFound is an internal sentinel returned by backend.Get when the
// requested credential does not exist.
var errNotFound = errors.New("keyring: credential not found")

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

// normalizeEmail normalizes an email address by trimming whitespace and
// lowercasing it.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// normalizeServer normalizes a server URL by trimming whitespace and removing
// the trailing slash.
func normalizeServer(url string) string {
	return strings.TrimRight(strings.TrimSpace(url), "/")
}

// normalizeRef returns a copy of ref with Email and ServerURL normalized.
func normalizeRef(ref session.AccountRef) session.AccountRef {
	return session.AccountRef{
		Email:     normalizeEmail(ref.Email),
		ServerURL: normalizeServer(ref.ServerURL),
	}
}

// ---------------------------------------------------------------------------
// Backend abstraction
// ---------------------------------------------------------------------------

// backend abstracts the OS keyring operations so production code can use
// the real zalando go-keyring library and tests can use a fake.
type backend interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

// zalandoBackend wraps github.com/zalando/go-keyring.
type zalandoBackend struct{}

func (zalandoBackend) Set(service, user, password string) error {
	return zaladokeyring.Set(service, user, password)
}

func (zalandoBackend) Get(service, user string) (string, error) {
	v, err := zaladokeyring.Get(service, user)
	if errors.Is(err, zaladokeyring.ErrNotFound) {
		return "", errNotFound
	}
	return v, err
}

func (zalandoBackend) Delete(service, user string) error {
	return zaladokeyring.Delete(service, user)
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

// Store implements out.CredentialStore backed by the OS secret service.
type Store struct {
	backend backend
}

// New creates a Store that uses the real OS keyring.
func New() *Store {
	return &Store{backend: zalandoBackend{}}
}

// NewForBackend creates a Store with the given backend (useful in tests).
func NewForBackend(b backend) *Store {
	return &Store{backend: b}
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

// refHash returns a stable hex-encoded SHA-256 hash of the normalized
// email and server URL fields in ref.
func refHash(ref session.AccountRef) string {
	n := normalizeRef(ref)
	h := sha256.Sum256([]byte(n.Email + "\x00" + n.ServerURL))
	return hex.EncodeToString(h[:])
}

// checkContext returns the context error if the context is already done.
func checkContext(ctx context.Context) error {
	err := ctx.Err()
	return err
}

func keyringLog(ctx context.Context, operation string) zerowrap.Logger {
	return zerowrap.Logger{Logger: zerowrap.FromCtx(ctx).
		With().
		Str(zerowrap.FieldComponent, "secrets.keyring").
		Str(zerowrap.FieldOperation, operation).
		Logger()}
}

func logKeyringStart(ctx context.Context, operation string) (zerowrap.Logger, time.Time) {
	started := time.Now()
	log := keyringLog(ctx, operation)
	log.Info().Msg("keyring operation started")
	return log, started
}

func logKeyringFinish(log zerowrap.Logger, started time.Time, err error) {
	event := log.Info()
	msg := "keyring operation finished"
	if err != nil {
		event = log.Error().Str("error_kind", safelog.SafeErrorKind(err))
		msg = "keyring operation failed"
	}
	event.Dur(zerowrap.FieldDuration, time.Since(started)).Msg(msg)
}

func logKeyringAvailability(log zerowrap.Logger, started time.Time, err error) {
	available := err == nil
	event := log.Info()
	msg := "keyring availability checked"
	if err != nil {
		event = log.Error().Str("error_kind", safelog.SafeErrorKind(err))
		msg = "keyring unavailable"
	}
	event.Bool("available", available).Dur(zerowrap.FieldDuration, time.Since(started)).Msg(msg)
}

// ---------------------------------------------------------------------------
// CredentialStore implementation
// ---------------------------------------------------------------------------

// CheckAvailable verifies that the OS secret service is reachable by
// setting, reading, and deleting a probe value.
func (s *Store) CheckAvailable(ctx context.Context) (retErr error) {
	log, started := logKeyringStart(ctx, "check_available")
	defer func() { logKeyringAvailability(log, started, retErr) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := s.backend.Set(serviceProbe, probeUser, probeValue); err != nil {
		return &coreerrors.Error{
			Kind:    coreerrors.KindUnsupported,
			Message: "Secret Service is required: " + err.Error(),
		}
	}

	if _, err := s.backend.Get(serviceProbe, probeUser); err != nil {
		// Clean up the probe set above.
		_ = s.backend.Delete(serviceProbe, probeUser)
		return &coreerrors.Error{
			Kind:    coreerrors.KindUnsupported,
			Message: "Secret Service is required: " + err.Error(),
		}
	}

	// Best-effort cleanup of the probe value.
	_ = s.backend.Delete(serviceProbe, probeUser)
	return nil
}

func (s *Store) SaveTokenBundle(ctx context.Context, ref session.AccountRef, bundle session.TokenBundle) (retErr error) {
	log, started := logKeyringStart(ctx, "save_token_bundle")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return err
	}

	clone := bundle.Clone()
	defer clone.Close()

	data, err := json.Marshal(clone)
	if err != nil {
		return err
	}

	key := refHash(ref)
	if err := s.backend.Set(serviceToken, key, string(data)); err != nil {
		return mapBackendError(err)
	}
	return nil
}

func (s *Store) LoadTokenBundle(ctx context.Context, ref session.AccountRef) (bundleResult session.TokenBundle, retErr error) {
	log, started := logKeyringStart(ctx, "load_token_bundle")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return session.TokenBundle{}, err
	}

	key := refHash(ref)
	data, err := s.backend.Get(serviceToken, key)
	if err != nil {
		return session.TokenBundle{}, mapBackendError(err)
	}

	var bundle session.TokenBundle
	if err := json.Unmarshal([]byte(data), &bundle); err != nil {
		return session.TokenBundle{}, err
	}

	// Validate that loaded metadata is consistent with the normalized ref.
	// refHash uses normalized values so the bundle was stored/looked up
	// under the same normalized key.  Normalize both sides before comparing.
	norm := normalizeRef(ref)

	if bundle.Email != "" && normalizeEmail(bundle.Email) != norm.Email {
		return session.TokenBundle{}, &coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Message: "loaded token bundle email does not match ref",
		}
	}
	if bundle.ServerURL != "" && normalizeServer(bundle.ServerURL) != norm.ServerURL {
		return session.TokenBundle{}, &coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Message: "loaded token bundle server URL does not match ref",
		}
	}

	// Fill in empty metadata from the ref so callers always have it.
	if bundle.Email == "" {
		bundle.Email = norm.Email
	}
	if bundle.ServerURL == "" {
		bundle.ServerURL = norm.ServerURL
	}

	return bundle, nil
}

func (s *Store) DeleteTokenBundle(ctx context.Context, ref session.AccountRef) (retErr error) {
	log, started := logKeyringStart(ctx, "delete_token_bundle")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return err
	}

	key := refHash(ref)
	err := s.backend.Delete(serviceToken, key)
	if errors.Is(err, errNotFound) {
		return nil
	}
	return err
}

func (s *Store) SaveUnlockEnvelope(ctx context.Context, ref session.AccountRef, envelope session.UnlockEnvelope) (retErr error) {
	log, started := logKeyringStart(ctx, "save_unlock_envelope")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return err
	}

	clone := envelope.Clone()
	defer clone.Close()

	data, err := json.Marshal(clone)
	if err != nil {
		return err
	}

	key := refHash(ref)
	if err := s.backend.Set(serviceUnlock, key, string(data)); err != nil {
		return mapBackendError(err)
	}
	return nil
}

func (s *Store) LoadUnlockEnvelope(ctx context.Context, ref session.AccountRef) (envelopeResult session.UnlockEnvelope, retErr error) {
	log, started := logKeyringStart(ctx, "load_unlock_envelope")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return session.UnlockEnvelope{}, err
	}

	key := refHash(ref)
	data, err := s.backend.Get(serviceUnlock, key)
	if err != nil {
		return session.UnlockEnvelope{}, mapBackendError(err)
	}

	var envelope session.UnlockEnvelope
	if err := json.Unmarshal([]byte(data), &envelope); err != nil {
		return session.UnlockEnvelope{}, err
	}

	return envelope, nil
}

func (s *Store) DeleteUnlockEnvelope(ctx context.Context, ref session.AccountRef) (retErr error) {
	log, started := logKeyringStart(ctx, "delete_unlock_envelope")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return err
	}

	key := refHash(ref)
	err := s.backend.Delete(serviceUnlock, key)
	if errors.Is(err, errNotFound) {
		return nil
	}
	return err
}

func (s *Store) SavePINProfile(ctx context.Context, ref session.AccountRef, profile session.PINProfile) (retErr error) {
	log, started := logKeyringStart(ctx, "save_pin_profile")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return err
	}

	norm := normalizeRef(ref)
	clone := profile.Clone()
	defer clone.Close()
	if err := clone.Validate(norm); err != nil {
		return &coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Message: "PIN profile does not match ref",
			Cause:   err,
		}
	}

	data, err := json.Marshal(clone)
	if err != nil {
		return err
	}

	key := refHash(norm)
	if err := s.backend.Set(servicePINProfile, key, string(data)); err != nil {
		return mapBackendError(err)
	}
	return nil
}

func (s *Store) LoadPINProfile(ctx context.Context, ref session.AccountRef) (profileResult session.PINProfile, retErr error) {
	log, started := logKeyringStart(ctx, "load_pin_profile")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return session.PINProfile{}, err
	}

	norm := normalizeRef(ref)
	key := refHash(norm)
	data, err := s.backend.Get(servicePINProfile, key)
	if err != nil {
		return session.PINProfile{}, mapBackendError(err)
	}

	var profile session.PINProfile
	if err := json.Unmarshal([]byte(data), &profile); err != nil {
		return session.PINProfile{}, err
	}
	if err := profile.Validate(norm); err != nil {
		profile.Close()
		return session.PINProfile{}, &coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Message: "loaded PIN profile does not match ref",
			Cause:   err,
		}
	}

	return profile, nil
}

func (s *Store) DeletePINProfile(ctx context.Context, ref session.AccountRef) (retErr error) {
	log, started := logKeyringStart(ctx, "delete_pin_profile")
	defer func() { logKeyringFinish(log, started, retErr) }()

	if err := checkContext(ctx); err != nil {
		return err
	}

	key := refHash(ref)
	err := s.backend.Delete(servicePINProfile, key)
	if errors.Is(err, errNotFound) {
		return nil
	}
	return err
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

// mapBackendError translates known backend errors into core domain errors.
func mapBackendError(err error) error {
	if errors.Is(err, errNotFound) {
		return &coreerrors.Error{
			Kind:    coreerrors.KindNotFound,
			Message: "credential not found",
		}
	}
	return err
}
