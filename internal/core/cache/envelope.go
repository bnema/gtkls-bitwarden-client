package cache

import "errors"

var (
	ErrInvalidVersion   = errors.New("cache: invalid snapshot version")
	ErrEmptyAccountHash = errors.New("cache: empty account hash")
	ErrEmptyVaultCipher = errors.New("cache: empty vault ciphertext")
)

func ValidateSnapshot(s Snapshot) error {
	if s.Version != Version {
		return ErrInvalidVersion
	}
	if s.AccountHash == "" {
		return ErrEmptyAccountHash
	}
	if len(s.VaultCiphertext) == 0 {
		return ErrEmptyVaultCipher
	}
	return nil
}
