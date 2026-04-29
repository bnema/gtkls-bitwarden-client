package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/out"
)

// outboxEnvelope is the on-disk envelope for encrypted outbox mutations.
type outboxEnvelope struct {
	Version    int       `json:"version"`
	SavedAt    time.Time `json:"saved_at"`
	Ciphertext []byte    `json:"ciphertext"`
}

// OutboxStore persists encrypted outbox mutations to a JSON file on disk.
type OutboxStore struct {
	path string
	box  out.SecretBox
}

// NewOutboxStore creates an OutboxStore that reads/writes the file at path
// using the given SecretBox for encryption.
func NewOutboxStore(path string, box out.SecretBox) *OutboxStore {
	return &OutboxStore{path: path, box: box}
}

// Path returns the file path this store uses.
func (s *OutboxStore) Path() string {
	return s.path
}

// Clear removes the outbox store file. No error if the file does not exist.
func (s *OutboxStore) Clear(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(s.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Load reads, decrypts, and unmarshals the outbox mutations from disk.
// Returns nil, nil if the file does not exist (absence is not an error).
// Requires box != nil and key non-empty when the file exists.
func (s *OutboxStore) Load(ctx context.Context, key []byte) ([]coresync.OutboxMutation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if s.box == nil {
		return nil, fmt.Errorf("outbox decrypt: secretbox unavailable")
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("outbox decrypt: empty key")
	}

	var env outboxEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("outbox decode envelope: %w", err)
	}

	plaintext, err := s.box.Open(env.Ciphertext, key)
	if err != nil {
		return nil, fmt.Errorf("outbox decrypt: %w", err)
	}

	var mutations []coresync.OutboxMutation
	if err := json.Unmarshal(plaintext, &mutations); err != nil {
		return nil, fmt.Errorf("outbox decode mutations: %w", err)
	}

	return mutations, nil
}

// Save encrypts and writes the outbox mutations to disk atomically.
// If mutations is empty, the file is removed (ignoring not-exist errors).
// Requires box != nil and key non-empty.
func (s *OutboxStore) Save(ctx context.Context, key []byte, mutations []coresync.OutboxMutation) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(mutations) == 0 {
		err := os.Remove(s.path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}

	if s.box == nil {
		return fmt.Errorf("outbox encrypt: secretbox unavailable")
	}
	if len(key) == 0 {
		return fmt.Errorf("outbox encrypt: empty key")
	}

	plaintext, err := json.Marshal(mutations)
	if err != nil {
		return fmt.Errorf("outbox marshal: %w", err)
	}

	ciphertext, err := s.box.Seal(plaintext, key)
	if err != nil {
		return fmt.Errorf("outbox encrypt: %w", err)
	}

	env := outboxEnvelope{
		Version:    1,
		SavedAt:    time.Now().UTC(),
		Ciphertext: ciphertext,
	}

	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("outbox marshal envelope: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// Write atomically: temp file in same directory, fsync, chmod, rename.
	tmpFile := s.path + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	if _, err := f.Write(data); err != nil {
		_ = os.Remove(tmpFile) // best-effort cleanup
		return err
	}

	if err := f.Sync(); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	if err := f.Chmod(0600); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	if err := ctx.Err(); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	return os.Rename(tmpFile, s.path)
}
