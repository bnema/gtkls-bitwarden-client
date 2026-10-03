package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bnema/zerowrap"
	"golang.org/x/crypto/argon2"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/cache"
	safelog "github.com/bnema/gtkls-bitwarden-client/internal/core/logging"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

const (
	cacheKeyArgonTime    uint32 = 3
	cacheKeyArgonMemory  uint32 = 64 * 1024
	cacheKeyArgonThreads uint8  = 4
	cacheKeySize                = 32
	cacheSaltSize               = 16
)

var (
	errCacheUnavailable = errors.New("cache store or secretbox unavailable")
	errNoCacheSalt      = errors.New("no cache salt available")
)

// decryptedCacheSnapshot is the plaintext form of the encrypted vault cache.
// It holds decoded domain values only; raw plaintext buffers never leave
// vaultCache.
type decryptedCacheSnapshot struct {
	Salt      []byte
	Items     []vault.Item
	Folders   []vault.Folder
	Outbox    []coresync.OutboxMutation
	Conflicts []coresync.Conflict
}

// vaultCache owns every encode/decode/crypto step of the encrypted vault
// cache: key derivation, envelope validation, decryption into a plain
// snapshot (merging the standalone outbox store), sealing and saving, and
// zeroing of intermediate plaintext buffers. It holds no mutable state and is
// safe for concurrent use; callers own serialization (Service.cacheSaveMu,
// saveSeq).
type vaultCache struct {
	store  out.CacheStore
	box    out.SecretBox
	outbox out.OutboxStore
}

func (s *Service) vaultCache() vaultCache {
	return vaultCache{store: s.deps.Cache, box: s.deps.SecretBox, outbox: s.deps.Outbox}
}

// Available reports whether encrypted snapshots can be read and written.
func (c vaultCache) Available() bool {
	return c.store != nil && c.box != nil
}

// deriveCacheKey derives the local encrypted-cache/outbox key from the master
// password and per-account salt. It intentionally does not log or persist the
// derived key.
func deriveCacheKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, cacheKeyArgonTime, cacheKeyArgonMemory, cacheKeyArgonThreads, cacheKeySize)
}

func newCacheSalt() ([]byte, error) {
	salt := make([]byte, cacheSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// OpenWithPassword derives the cache key from password and the persisted salt
// (or a fresh random salt when there is no usable snapshot) and loads the
// snapshot. data.Salt is always the salt the returned key was derived from.
// loaded reports whether a snapshot was found and decrypted. On error the
// returned key is nil. The standalone outbox is merged only when a snapshot
// was loaded.
func (c vaultCache) OpenWithPassword(ctx context.Context, password string) (key []byte, data decryptedCacheSnapshot, loaded bool, err error) {
	log, started := logAppServiceStart(ctx, "cache_load_data")
	defer func() {
		logAppServiceFinishCount(log, started, err, len(data.Items)+len(data.Folders)+len(data.Outbox))
	}()

	salt, err := newCacheSalt()
	if err != nil {
		return nil, decryptedCacheSnapshot{}, false, fmt.Errorf("cache salt: %w", err)
	}
	fresh := func() ([]byte, decryptedCacheSnapshot, bool, error) {
		return deriveCacheKey(password, salt), decryptedCacheSnapshot{Salt: salt}, false, nil
	}

	if c.store == nil {
		return fresh()
	}
	env, found, err := c.loadEnvelope(ctx)
	if err != nil {
		return nil, decryptedCacheSnapshot{}, false, err
	}
	if !found {
		return fresh()
	}

	// Prefer the persisted random salt. Fresh first-run/no-cache salts are
	// persisted with the next encrypted cache save.
	if len(env.CacheKeySalt) > 0 {
		salt = append([]byte(nil), env.CacheKeySalt...)
	}
	key = deriveCacheKey(password, salt)

	if c.box == nil {
		clear(key)
		return nil, decryptedCacheSnapshot{}, false, errors.New("cache decrypt: secretbox unavailable")
	}
	data, err = c.decrypt(env, key)
	if err != nil {
		clear(key)
		return nil, decryptedCacheSnapshot{}, false, err
	}
	data.Salt = salt
	data.Outbox = c.mergeStandaloneOutbox(ctx, log, key, data.Outbox)
	return key, data, true, nil
}

// Open loads and decrypts the snapshot with an already derived key (for
// example from a PIN unlock envelope) and merges the standalone outbox. A
// missing, empty or unavailable cache yields an empty snapshot (plus any
// standalone outbox) and a nil error. data.Salt is the persisted salt.
func (c vaultCache) Open(ctx context.Context, key []byte) (data decryptedCacheSnapshot, err error) {
	log, started := logAppServiceStart(ctx, "cache_load_with_material")
	defer func() {
		logAppServiceFinishCount(log, started, err, len(data.Items)+len(data.Folders)+len(data.Outbox))
	}()

	if len(key) == 0 {
		return decryptedCacheSnapshot{}, nil
	}
	if !c.Available() {
		return decryptedCacheSnapshot{Outbox: c.mergeStandaloneOutbox(ctx, log, key, nil)}, nil
	}
	env, found, err := c.loadEnvelope(ctx)
	if err != nil {
		return decryptedCacheSnapshot{}, err
	}
	if !found {
		return decryptedCacheSnapshot{Outbox: c.mergeStandaloneOutbox(ctx, log, key, nil)}, nil
	}
	data, err = c.decrypt(env, key)
	if err != nil {
		return decryptedCacheSnapshot{}, err
	}
	data.Outbox = c.mergeStandaloneOutbox(ctx, log, key, data.Outbox)
	return data, nil
}

// Save seals data under key and persists it. If data.Salt is empty the salt of
// the existing snapshot is reused; errNoCacheSalt is returned if none exists.
// It does not touch the standalone outbox store (see SaveOutbox).
func (c vaultCache) Save(ctx context.Context, key []byte, accountHash string, data decryptedCacheSnapshot) error {
	if !c.Available() {
		return errCacheUnavailable
	}
	salt := c.resolveSalt(ctx, data.Salt)
	if len(salt) == 0 {
		return errNoCacheSalt
	}

	var buffers [][]byte
	defer func() {
		for _, b := range buffers {
			clear(b)
		}
	}()
	marshal := func(what string, v any) ([]byte, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("cache marshal %s: %w", what, err)
		}
		buffers = append(buffers, b)
		return b, nil
	}

	var plain cache.PlainSnapshot
	var err error
	if plain.ItemsJSON, err = marshal("items", data.Items); err != nil {
		return err
	}
	if plain.FoldersJSON, err = marshal("folders", data.Folders); err != nil {
		return err
	}
	if plain.OutboxJSON, err = marshal("outbox", data.Outbox); err != nil {
		return err
	}
	if plain.ConflictsJSON, err = marshal("conflicts", data.Conflicts); err != nil {
		return err
	}
	plain.AccountHash = accountHash
	plain.SavedAt = time.Now().UTC()
	plain.CacheKeySalt = salt
	plainJSON, err := marshal("snapshot", plain)
	if err != nil {
		return err
	}

	ciphertext, err := c.box.Seal(plainJSON, key)
	if err != nil {
		return fmt.Errorf("cache encrypt: %w", err)
	}
	return c.store.Save(ctx, cache.Snapshot{
		Version:         cache.Version,
		AccountHash:     accountHash,
		SavedAt:         plain.SavedAt,
		CacheKeySalt:    append([]byte(nil), salt...),
		VaultCiphertext: ciphertext,
	})
}

// SaveOutbox persists outbox to the standalone encrypted outbox store, if one
// is configured.
func (c vaultCache) SaveOutbox(ctx context.Context, key []byte, outbox []coresync.OutboxMutation) error {
	if c.outbox == nil {
		return nil
	}
	return c.outbox.Save(ctx, key, outbox)
}

// resolveSalt returns salt, or the persisted salt of the existing snapshot
// when salt is empty. It returns nil if neither is available.
func (c vaultCache) resolveSalt(ctx context.Context, salt []byte) []byte {
	if len(salt) > 0 {
		return append([]byte(nil), salt...)
	}
	if c.store == nil {
		return nil
	}
	if existing, err := c.store.Load(ctx); err == nil && len(existing.CacheKeySalt) > 0 {
		return append([]byte(nil), existing.CacheKeySalt...)
	}
	return nil
}

// loadEnvelope loads and validates the stored snapshot. found is false (with a
// nil error) when the store has no snapshot or only an empty one.
func (c vaultCache) loadEnvelope(ctx context.Context) (env cache.Snapshot, found bool, err error) {
	env, err = c.store.Load(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache.Snapshot{}, false, nil
		}
		return cache.Snapshot{}, false, fmt.Errorf("cache load: %w", err)
	}
	if env.Version == 0 && env.AccountHash == "" && len(env.VaultCiphertext) == 0 {
		return cache.Snapshot{}, false, nil
	}
	if err := cache.ValidateSnapshot(env); err != nil {
		return cache.Snapshot{}, false, fmt.Errorf("cache validation: %w", err)
	}
	return env, true, nil
}

// decrypt opens env with key and decodes it. All plaintext buffers are zeroed
// on every return path.
func (c vaultCache) decrypt(env cache.Snapshot, key []byte) (decryptedCacheSnapshot, error) {
	var data decryptedCacheSnapshot

	plaintext, err := c.box.Open(env.VaultCiphertext, key)
	if err != nil {
		return data, fmt.Errorf("cache decrypt: %w", err)
	}
	defer clear(plaintext)

	var plain cache.PlainSnapshot
	defer func() {
		clear(plain.ItemsJSON)
		clear(plain.FoldersJSON)
		clear(plain.OutboxJSON)
		clear(plain.ConflictsJSON)
	}()
	if err := json.Unmarshal(plaintext, &plain); err != nil {
		return data, fmt.Errorf("cache decode: %w", err)
	}

	if err := json.Unmarshal(plain.ItemsJSON, &data.Items); err != nil {
		return decryptedCacheSnapshot{}, fmt.Errorf("cache items decode: %w", err)
	}
	if err := json.Unmarshal(plain.FoldersJSON, &data.Folders); err != nil {
		return decryptedCacheSnapshot{}, fmt.Errorf("cache folders decode: %w", err)
	}
	if len(plain.OutboxJSON) > 0 {
		if err := json.Unmarshal(plain.OutboxJSON, &data.Outbox); err != nil {
			return decryptedCacheSnapshot{}, fmt.Errorf("cache outbox decode: %w", err)
		}
	}
	if len(plain.ConflictsJSON) > 0 {
		if err := json.Unmarshal(plain.ConflictsJSON, &data.Conflicts); err != nil {
			return decryptedCacheSnapshot{}, fmt.Errorf("cache conflicts decode: %w", err)
		}
	}
	data.Salt = append([]byte(nil), env.CacheKeySalt...)
	return data, nil
}

// mergeStandaloneOutbox appends mutations from the standalone outbox store to
// existing and dedupes by mutation ID. A store failure is logged and ignored.
func (c vaultCache) mergeStandaloneOutbox(ctx context.Context, log zerowrap.Logger, key []byte, existing []coresync.OutboxMutation) []coresync.OutboxMutation {
	if c.outbox != nil && len(key) > 0 {
		stored, err := c.outbox.Load(ctx, key)
		if err != nil {
			log.Warn().
				Str(zerowrap.FieldOperation, "outbox_load").
				Str("error_kind", safelog.SafeErrorKind(err)).
				Msg("outbox load skipped")
		} else {
			existing = append(existing, stored...)
		}
	}
	return dedupeOutboxMutations(existing)
}

func dedupeOutboxMutations(outbox []coresync.OutboxMutation) []coresync.OutboxMutation {
	seen := make(map[string]struct{}, len(outbox))
	deduped := make([]coresync.OutboxMutation, 0, len(outbox))
	for _, mutation := range outbox {
		if _, ok := seen[mutation.ID]; ok {
			continue
		}
		seen[mutation.ID] = struct{}{}
		deduped = append(deduped, mutation)
	}
	return deduped
}
