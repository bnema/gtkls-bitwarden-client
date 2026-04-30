package pinenvelope

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	session "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Sentinel errors returned by the service.
var (
	ErrInvalidPIN      = errors.New("pinenvelope: invalid PIN")
	ErrInvalidEnvelope = errors.New("pinenvelope: invalid envelope fields")
)

// ServiceConfig holds the tunable parameters for the PIN envelope service.
// Zero-valued fields are replaced by their defaults inside New.
type ServiceConfig struct {
	TTL         time.Duration
	MaxFailures int
	KDFTime     uint32
	KDFMemory   uint32
	KDFThreads  uint8
}

const (
	defaultTTL         = 8 * time.Hour
	defaultMaxFailures = 5
	defaultKDFTime     = 3
	defaultKDFMemory   = 64 * 1024
	defaultKDFThreads  = 4

	saltSize = 16
)

// Service creates and opens PIN-protected unlock envelopes.
type Service struct {
	cfg ServiceConfig
}

// New returns a Service with defaults applied for any zero-valued fields in
// the supplied configuration.
func New(cfg ServiceConfig) Service {
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = defaultMaxFailures
	}
	if cfg.KDFTime == 0 {
		cfg.KDFTime = defaultKDFTime
	}
	if cfg.KDFMemory == 0 {
		cfg.KDFMemory = defaultKDFMemory
	}
	if cfg.KDFThreads == 0 {
		cfg.KDFThreads = defaultKDFThreads
	}
	return Service{cfg: cfg}
}

// Create derives a key from pin, encrypts material and returns a new
// UnlockEnvelope.  It validates that pin and bootID are non-empty and that
// material carries at least one of CacheKey or UserKey.
func (s Service) Create(
	ctx context.Context,
	ref session.AccountRef,
	material session.UnlockMaterial,
	pin string,
	bootID string,
) (session.UnlockEnvelope, error) {
	if pin == "" {
		return session.UnlockEnvelope{}, ErrInvalidPIN
	}
	if bootID == "" {
		return session.UnlockEnvelope{}, errors.New("pinenvelope: bootID must not be empty")
	}
	if len(material.CacheKey) == 0 && len(material.UserKey) == 0 {
		return session.UnlockEnvelope{}, errors.New("pinenvelope: UnlockMaterial must have at least one of CacheKey or UserKey")
	}

	// Generate a random 16-byte salt.
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return session.UnlockEnvelope{}, err
	}

	// Derive a 32-byte key via Argon2id.
	key := argon2.IDKey(
		[]byte(pin),
		salt,
		s.cfg.KDFTime,
		s.cfg.KDFMemory,
		s.cfg.KDFThreads,
		chacha20poly1305.KeySize,
	)

	// Clone and marshal the unlock material.
	plaintext, err := json.Marshal(material.Clone())
	if err != nil {
		clear(key)
		return session.UnlockEnvelope{}, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		clear(key)
		return session.UnlockEnvelope{}, err
	}

	// Generate a random 24-byte nonce for XChaCha20-Poly1305.
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		clear(key)
		return session.UnlockEnvelope{}, err
	}

	// Encrypt and prepend the nonce.
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	clear(key)
	clear(plaintext)

	stored := make([]byte, len(nonce)+len(ciphertext))
	copy(stored[:len(nonce)], nonce)
	copy(stored[len(nonce):], ciphertext)

	now := time.Now().UTC()
	return session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		BootID:         bootID,
		ExpiresAt:      now.Add(s.cfg.TTL),
		KDF:            "argon2id",
		KDFTime:        s.cfg.KDFTime,
		KDFMemory:      s.cfg.KDFMemory,
		KDFThreads:     s.cfg.KDFThreads,
		Salt:           salt,
		Ciphertext:     stored,
		PINMaxFailures: s.cfg.MaxFailures,
	}, nil
}

// Open decrypts the envelope with the supplied PIN and returns the unlock
// material together with an updated envelope (which may carry incremented
// failure counters or backoff).
//
// On a validation error (expired envelope, boot changed, etc.) the returned
// updated envelope retains the original counters.
//
// On an incorrect PIN the returned material is empty, the updated envelope
// has an incremented FailedAttempts counter and an appropriate BackoffUntil,
// and the error is ErrInvalidPIN.
func (s Service) Open(
	ctx context.Context,
	ref session.AccountRef,
	envelope session.UnlockEnvelope,
	pin string,
	bootID string,
) (session.UnlockMaterial, session.UnlockEnvelope, error) {
	updated := envelope
	now := time.Now().UTC()

	if err := ctx.Err(); err != nil {
		return session.UnlockMaterial{}, updated, err
	}

	// Validate expiry, boot, account and backoff.
	if err := updated.Validate(ref, bootID, now); err != nil {
		// Do not increment failure counters for these errors.
		return session.UnlockMaterial{}, updated, err
	}

	if err := validateOpenEnvelope(updated, pin); err != nil {
		return session.UnlockMaterial{}, updated, err
	}

	// Derive the key from the PIN and stored KDF parameters.
	key := argon2.IDKey(
		[]byte(pin),
		updated.Salt,
		updated.KDFTime,
		updated.KDFMemory,
		updated.KDFThreads,
		chacha20poly1305.KeySize,
	)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		clear(key)
		return session.UnlockMaterial{}, updated, err
	}
	clear(key)

	nonceSize := aead.NonceSize()
	if len(updated.Ciphertext) < nonceSize {
		return session.UnlockMaterial{}, updated, ErrInvalidEnvelope
	}

	nonce := updated.Ciphertext[:nonceSize]
	cipherdata := updated.Ciphertext[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, cipherdata, nil)
	if err != nil {
		updated.RecordPINFailure(now)
		return session.UnlockMaterial{}, updated, ErrInvalidPIN
	}

	var material session.UnlockMaterial
	if err := json.Unmarshal(plaintext, &material); err != nil {
		clear(plaintext)
		return session.UnlockMaterial{}, updated, err
	}
	clear(plaintext)

	// Reset failure counters on successful unlock.
	updated.FailedAttempts = 0
	updated.BackoffUntil = time.Time{}

	return material, updated, nil
}

// validateOpenEnvelope performs consistency checks on the envelope fields that
// are unrelated to expiry, boot or account validation.
func validateOpenEnvelope(e session.UnlockEnvelope, pin string) error {
	if pin == "" {
		return ErrInvalidPIN
	}
	if e.Version != session.UnlockEnvelopeVersion {
		return ErrInvalidEnvelope
	}
	if e.KDF != "argon2id" {
		return ErrInvalidEnvelope
	}
	if len(e.Salt) != saltSize {
		return ErrInvalidEnvelope
	}
	if len(e.Ciphertext) == 0 {
		return ErrInvalidEnvelope
	}
	return nil
}
