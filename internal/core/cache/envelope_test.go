package cache

import (
	"testing"
	"time"
)

func TestValidateSnapshotValid(t *testing.T) {
	s := Snapshot{
		Version:          Version,
		AccountHash:      "abc123",
		LastRevision:     "rev1",
		SavedAt:          time.Now(),
		VaultCiphertext:  []byte("encrypted-data"),
		OutboxCiphertext: []byte("outbox-data"),
	}
	if err := ValidateSnapshot(s); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestValidateSnapshotWrongVersion(t *testing.T) {
	s := Snapshot{
		Version:         99,
		AccountHash:     "abc123",
		VaultCiphertext: []byte("data"),
	}
	if err := ValidateSnapshot(s); err != ErrInvalidVersion {
		t.Errorf("expected ErrInvalidVersion, got %v", err)
	}
}

func TestValidateSnapshotEmptyAccountHash(t *testing.T) {
	s := Snapshot{
		Version:         Version,
		AccountHash:     "",
		VaultCiphertext: []byte("data"),
	}
	if err := ValidateSnapshot(s); err != ErrEmptyAccountHash {
		t.Errorf("expected ErrEmptyAccountHash, got %v", err)
	}
}

func TestValidateSnapshotEmptyVaultCiphertext(t *testing.T) {
	s := Snapshot{
		Version:         Version,
		AccountHash:     "abc123",
		VaultCiphertext: nil,
	}
	if err := ValidateSnapshot(s); err != ErrEmptyVaultCipher {
		t.Errorf("expected ErrEmptyVaultCipher, got %v", err)
	}
}

func TestValidateSnapshotEmptyVaultCiphertextSlice(t *testing.T) {
	s := Snapshot{
		Version:         Version,
		AccountHash:     "abc123",
		VaultCiphertext: []byte{},
	}
	if err := ValidateSnapshot(s); err != ErrEmptyVaultCipher {
		t.Errorf("expected ErrEmptyVaultCipher, got %v", err)
	}
}
