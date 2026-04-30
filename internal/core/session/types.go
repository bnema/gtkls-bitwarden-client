package session

import "time"

// AccountRef identifies an account by email and server URL.
type AccountRef struct {
	Email     string `json:"email"`
	ServerURL string `json:"serverUrl"`
}

// TokenBundle holds OAuth tokens and associated metadata.
type TokenBundle struct {
	AccountID    string    `json:"accountId"`
	Email        string    `json:"email"`
	ServerURL    string    `json:"serverUrl"`
	AccessToken  []byte    `json:"accessToken"`
	RefreshToken []byte    `json:"refreshToken"`
	TokenType    string    `json:"tokenType"`
	ExpiresAt    time.Time `json:"expiresAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
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
	return c
}

// Close zeroes the backing arrays of secret slices and nils them.
func (tb *TokenBundle) Close() {
	clear(tb.AccessToken)
	clear(tb.RefreshToken)
	tb.AccessToken = nil
	tb.RefreshToken = nil
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

// AuthStatus describes the authentication state of a session.
type AuthStatus string

const (
	KeyringUnavailable      AuthStatus = "keyring_unavailable"
	Unauthenticated         AuthStatus = "unauthenticated"
	LoggedInLocked          AuthStatus = "logged_in_locked"
	LoggedInUnlockAvailable AuthStatus = "logged_in_unlock_available"
)
