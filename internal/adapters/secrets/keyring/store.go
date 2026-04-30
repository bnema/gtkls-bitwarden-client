package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	zaladokeyring "github.com/zalando/go-keyring"

	coreerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	session "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
)

// Service names and probe user for the OS keyring.
const (
	serviceToken  = "gtk4-layershell-bitwarden/token"
	serviceUnlock = "gtk4-layershell-bitwarden/unlock"
	serviceProbe  = "gtk4-layershell-bitwarden/probe"
	probeUser     = "availability"
	probeValue    = "ok"
)

// errNotFound is an internal sentinel returned by backend.Get when the
// requested credential does not exist.
var errNotFound = errors.New("keyring: credential not found")

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
	email := strings.ToLower(strings.TrimSpace(ref.Email))
	server := strings.TrimRight(strings.TrimSpace(ref.ServerURL), "/")
	h := sha256.Sum256([]byte(email + "\x00" + server))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// CredentialStore implementation
// ---------------------------------------------------------------------------

// CheckAvailable verifies that the OS secret service is reachable by
// setting, reading, and deleting a probe value.
func (s *Store) CheckAvailable(ctx context.Context) error {
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

func (s *Store) SaveTokenBundle(ctx context.Context, ref session.AccountRef, bundle session.TokenBundle) error {
	clone := bundle.Clone()

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

func (s *Store) LoadTokenBundle(ctx context.Context, ref session.AccountRef) (session.TokenBundle, error) {
	key := refHash(ref)
	data, err := s.backend.Get(serviceToken, key)
	if err != nil {
		return session.TokenBundle{}, mapBackendError(err)
	}

	var bundle session.TokenBundle
	if err := json.Unmarshal([]byte(data), &bundle); err != nil {
		return session.TokenBundle{}, err
	}

	// Validate that loaded metadata is consistent with the requested ref.
	if bundle.Email != "" && bundle.Email != ref.Email {
		return session.TokenBundle{}, &coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Message: "loaded token bundle email does not match ref",
		}
	}
	if bundle.ServerURL != "" && bundle.ServerURL != ref.ServerURL {
		return session.TokenBundle{}, &coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Message: "loaded token bundle server URL does not match ref",
		}
	}

	// Fill in empty metadata from the ref so callers always have it.
	if bundle.Email == "" {
		bundle.Email = ref.Email
	}
	if bundle.ServerURL == "" {
		bundle.ServerURL = ref.ServerURL
	}

	return bundle, nil
}

func (s *Store) DeleteTokenBundle(ctx context.Context, ref session.AccountRef) error {
	key := refHash(ref)
	err := s.backend.Delete(serviceToken, key)
	if errors.Is(err, errNotFound) {
		return nil
	}
	return err
}

func (s *Store) SaveUnlockEnvelope(ctx context.Context, ref session.AccountRef, envelope session.UnlockEnvelope) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	key := refHash(ref)
	if err := s.backend.Set(serviceUnlock, key, string(data)); err != nil {
		return mapBackendError(err)
	}
	return nil
}

func (s *Store) LoadUnlockEnvelope(ctx context.Context, ref session.AccountRef) (session.UnlockEnvelope, error) {
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

func (s *Store) DeleteUnlockEnvelope(ctx context.Context, ref session.AccountRef) error {
	key := refHash(ref)
	err := s.backend.Delete(serviceUnlock, key)
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
