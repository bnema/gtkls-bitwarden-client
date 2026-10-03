package session

import "time"

// AccountRef identifies an account by email and server URL.
type AccountRef struct {
	Email     string `json:"email"`
	ServerURL string `json:"serverUrl"`
}

// TokenBundle holds OAuth tokens and associated metadata.
type TokenBundle struct {
	AccountID                string    `json:"accountId"`
	Email                    string    `json:"email"`
	ServerURL                string    `json:"serverUrl"`
	AccessToken              []byte    `json:"accessToken"`
	RefreshToken             []byte    `json:"refreshToken"`
	RememberedTwoFactorToken []byte    `json:"rememberedTwoFactorToken"`
	TokenType                string    `json:"tokenType"`
	ExpiresAt                time.Time `json:"expiresAt"`
	UpdatedAt                time.Time `json:"updatedAt"`
}

// Clone returns a deep copy of the TokenBundle.
func (tb TokenBundle) Clone() TokenBundle {
	c := tb
	if tb.AccessToken != nil {
		c.AccessToken = make([]byte, len(tb.AccessToken))
		copy(c.AccessToken, tb.AccessToken)
	}
	if tb.RefreshToken != nil {
		c.RefreshToken = make([]byte, len(tb.RefreshToken))
		copy(c.RefreshToken, tb.RefreshToken)
	}
	if tb.RememberedTwoFactorToken != nil {
		c.RememberedTwoFactorToken = make([]byte, len(tb.RememberedTwoFactorToken))
		copy(c.RememberedTwoFactorToken, tb.RememberedTwoFactorToken)
	}
	return c
}

// Close zeroes the backing arrays of secret slices and nils them.
func (tb *TokenBundle) Close() {
	clear(tb.AccessToken)
	clear(tb.RefreshToken)
	clear(tb.RememberedTwoFactorToken)
	tb.AccessToken = nil
	tb.RefreshToken = nil
	tb.RememberedTwoFactorToken = nil
}

// UnlockMaterial holds sensitive key material for unlocking the vault.
type UnlockMaterial struct {
	CacheKey []byte `json:"cacheKey"`
	UserKey  []byte `json:"userKey"`
}

// Clone returns a deep copy of the UnlockMaterial.
func (um UnlockMaterial) Clone() UnlockMaterial {
	c := um
	if um.CacheKey != nil {
		c.CacheKey = make([]byte, len(um.CacheKey))
		copy(c.CacheKey, um.CacheKey)
	}
	if um.UserKey != nil {
		c.UserKey = make([]byte, len(um.UserKey))
		copy(c.UserKey, um.UserKey)
	}
	return c
}

// Close zeroes the backing arrays of secret slices and nils them.
func (um *UnlockMaterial) Close() {
	clear(um.CacheKey)
	clear(um.UserKey)
	um.CacheKey = nil
	um.UserKey = nil
}

// UnlockEnvelopeVersion is the current envelope format version.
const UnlockEnvelopeVersion = 1

// UnlockEnvelope contains all data needed to store and validate a derived key
// unlock token in the OS keyring.
type UnlockEnvelope struct {
	Version        int        `json:"version"`
	Account        AccountRef `json:"account"`
	AccountID      string     `json:"accountId"`
	BootID         string     `json:"bootId"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	KDF            string     `json:"kdf"`
	KDFTime        uint32     `json:"kdfTime"`
	KDFMemory      uint32     `json:"kdfMemory"`
	KDFThreads     uint8      `json:"kdfThreads"`
	Salt           []byte     `json:"salt"`
	Ciphertext     []byte     `json:"ciphertext"`
	FailedAttempts int        `json:"failedAttempts"`
	PINMaxFailures int        `json:"pinMaxFailures"`
	BackoffUntil   time.Time  `json:"backoffUntil"`
}

// Clone returns a deep copy of the UnlockEnvelope, deep-copying Salt and
// Ciphertext slices.
func (e UnlockEnvelope) Clone() UnlockEnvelope {
	c := e
	if e.Salt != nil {
		c.Salt = make([]byte, len(e.Salt))
		copy(c.Salt, e.Salt)
	}
	if e.Ciphertext != nil {
		c.Ciphertext = make([]byte, len(e.Ciphertext))
		copy(c.Ciphertext, e.Ciphertext)
	}
	return c
}

// Close zeroes the backing arrays of Salt and Ciphertext and nils them.
func (e *UnlockEnvelope) Close() {
	clear(e.Salt)
	clear(e.Ciphertext)
	e.Salt = nil
	e.Ciphertext = nil
}

// AuthStatus describes the authentication state of a session.
type AuthStatus string

const (
	KeyringUnavailable      AuthStatus = "keyring_unavailable"
	Unauthenticated         AuthStatus = "unauthenticated"
	LoggedInLocked          AuthStatus = "logged_in_locked"
	LoggedInUnlockAvailable AuthStatus = "logged_in_unlock_available"
)

// AuthStatusReason describes why the current AuthStatus applies.
type AuthStatusReason string

const (
	AuthReasonNone                AuthStatusReason = "none"
	AuthReasonKeyringUnavailable  AuthStatusReason = "keyring_unavailable"
	AuthReasonNoToken             AuthStatusReason = "no_token"
	AuthReasonNoPINProfile        AuthStatusReason = "no_pin_profile"
	AuthReasonNoEnvelope          AuthStatusReason = "no_envelope"
	AuthReasonBootChanged         AuthStatusReason = "boot_changed"
	AuthReasonPINBackoff          AuthStatusReason = "pin_backoff"
	AuthReasonAccountMismatch     AuthStatusReason = "account_mismatch"
	AuthReasonEnvelopeInvalid     AuthStatusReason = "envelope_invalid"
	AuthReasonSoftUnlockAvailable AuthStatusReason = "soft_unlock_available"
)

// AuthStatusDetail provides comprehensive authentication state for UX decisions.
type AuthStatusDetail struct {
	Status              AuthStatus       `json:"status"`
	Reason              AuthStatusReason `json:"reason"`
	HasToken            bool             `json:"hasToken"`
	HasPINProfile       bool             `json:"hasPinProfile"`
	HasEnvelope         bool             `json:"hasEnvelope"`
	EnvelopeValid       bool             `json:"envelopeValid"`
	SoftUnlockAvailable bool             `json:"softUnlockAvailable"`
}

// UnlockStep names the next action an account must take to reach an unlocked
// vault. It is derived from AuthStatusDetail so every front end (CLI, GUI)
// shares one decision about whether PIN unlock is possible and what the user
// has to do otherwise.
type UnlockStep string

const (
	// UnlockStepFixKeyring means the OS secret service is unavailable.
	UnlockStepFixKeyring UnlockStep = "fix_keyring"
	// UnlockStepPIN means the local unlock envelope is usable: PIN alone unlocks.
	UnlockStepPIN UnlockStep = "pin"
	// UnlockStepRenewEnvelope means a PIN profile exists but the envelope is
	// missing or unusable: the master password renews it.
	UnlockStepRenewEnvelope UnlockStep = "renew_envelope"
	// UnlockStepSetupPIN means the account is logged in without a PIN profile:
	// the master password plus a new PIN are required.
	UnlockStepSetupPIN UnlockStep = "setup_pin"
	// UnlockStepWait means PIN attempts are in backoff: retry later.
	UnlockStepWait UnlockStep = "wait"
	// UnlockStepLogin means no usable login exists for the account.
	UnlockStepLogin UnlockStep = "login"
)

// CanPINUnlock reports whether the account can be unlocked with the PIN alone.
func (d AuthStatusDetail) CanPINUnlock() bool {
	return d.Status == LoggedInUnlockAvailable && d.SoftUnlockAvailable
}

// NextStep returns the action required to unlock the account.
func (d AuthStatusDetail) NextStep() UnlockStep {
	switch {
	case d.Status == KeyringUnavailable:
		return UnlockStepFixKeyring
	case d.CanPINUnlock():
		return UnlockStepPIN
	case d.Reason == AuthReasonPINBackoff:
		return UnlockStepWait
	case d.Status == LoggedInUnlockAvailable || d.Status == LoggedInLocked:
		if d.HasPINProfile {
			return UnlockStepRenewEnvelope
		}
		return UnlockStepSetupPIN
	default:
		return UnlockStepLogin
	}
}
