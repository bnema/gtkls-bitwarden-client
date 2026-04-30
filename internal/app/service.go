package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/cache"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	cerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"golang.org/x/crypto/argon2"
)

const (
	cacheKeyArgonTime    uint32 = 3
	cacheKeyArgonMemory  uint32 = 64 * 1024
	cacheKeyArgonThreads uint8  = 4
	cacheKeySize                = 32
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
func (s *Service) Login(ctx context.Context, input auth.LoginInput) error {
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

	// 3. Perform remote login and cache load exactly once.
	if err := s.unlock(ctx, input.Email, input.Password, input.TwoFactorPrompt); err != nil {
		return err
	}

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

	// 8. Create PIN-protected unlock envelope.
	envelope, err := s.deps.PINEnvelope.Create(ctx, ref, unlockMaterial, pin, bootID)
	if err != nil {
		return fmt.Errorf("app: create envelope: %w", err)
	}

	// Set AccountID from token bundle if available.
	if tokens.AccountID != "" {
		envelope.AccountID = tokens.AccountID
	}

	// 9. Persist token bundle and unlock envelope.
	if err := s.deps.Credentials.SaveTokenBundle(ctx, ref, tokens); err != nil {
		envelope.Close()
		return fmt.Errorf("app: save token bundle: %w", err)
	}
	if err := s.deps.Credentials.SaveUnlockEnvelope(ctx, ref, envelope); err != nil {
		// Best-effort clean up token bundle on envelope save failure.
		_ = s.deps.Credentials.DeleteTokenBundle(ctx, ref)
		envelope.Close()
		return fmt.Errorf("app: save unlock envelope: %w", err)
	}

	return nil
}

// Unlock transitions the service from locked to unlocked.
func (s *Service) Unlock(ctx context.Context, email, password string) (retErr error) {
	return s.unlock(ctx, email, password, nil)
}

// UnlockWithTwoFactor transitions the service from locked to unlocked, prompting
// for a two-factor code when the remote requires it.
func (s *Service) UnlockWithTwoFactor(ctx context.Context, email, password string, prompt auth.TwoFactorPrompt) error {
	return s.unlock(ctx, email, password, prompt)
}

// UnlockWithPIN unlocks the vault using a previously-stored PIN unlock envelope.
// It loads the token bundle and unlock envelope from the credential store, opens
// the envelope with the provided PIN, and restores the remote session. On PIN
// mismatch, failure counters are persisted; after max failures the envelope is
// deleted. Expired, boot-changed, and other validation errors are returned
// without restoring the session.
func (s *Service) UnlockWithPIN(ctx context.Context, email, pin string) (retErr error) {
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

	// 5. Load unlock envelope.
	envelope, err := s.deps.Credentials.LoadUnlockEnvelope(ctx, ref)
	if err != nil {
		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return fmt.Errorf("app: unlock-pin: load envelope: %w", err)
	}

	// 6. Get boot ID.
	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil {
		s.mu.Lock()
		s.state = auth.LockStateLocked
		s.mu.Unlock()
		return fmt.Errorf("app: unlock-pin: boot id: %w", err)
	}

	// 7. Open the PIN envelope.
	material, opened, openErr := s.deps.PINEnvelope.Open(ctx, ref, envelope, pin, bootID)

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

	// Start background sync worker rooted at context.Background().
	workerCtx, cancel := context.WithCancel(context.Background())
	s.cancelWorkers = cancel
	s.emit(Unlocking, "starting sync worker")

	s.startMinimalSyncWorker(workerCtx)

	return nil
}

// loadCacheData loads and decrypts a cached vault snapshot, returning the
// items, folders, outbox mutations, derived cache key, salt, and whether
// data was loaded. It does NOT install state on the service.
func (s *Service) loadCacheData(ctx context.Context, password string) (items []vault.Item, folders []vault.Folder, outbox []coresync.OutboxMutation, key []byte, salt []byte, loaded bool, err error) {
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

	var plain cache.PlainSnapshot
	if err := json.Unmarshal(plaintext, &plain); err != nil {
		return nil, nil, nil, nil, nil, false, fmt.Errorf("cache decode: %w", err)
	}

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
func (s *Service) loadCachedVaultWithKey(ctx context.Context, key []byte) ([]vault.Item, []vault.Folder, []coresync.OutboxMutation, error) {
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

	var plain cache.PlainSnapshot
	if err := json.Unmarshal(plaintext, &plain); err != nil {
		return nil, nil, nil, fmt.Errorf("cache decode: %w", err)
	}

	// Zero plaintext bytes after decode.
	clear(plaintext)

	var items []vault.Item
	if err := json.Unmarshal(plain.ItemsJSON, &items); err != nil {
		return nil, nil, nil, fmt.Errorf("cache items decode: %w", err)
	}

	var folders []vault.Folder
	if err := json.Unmarshal(plain.FoldersJSON, &folders); err != nil {
		return nil, nil, nil, fmt.Errorf("cache folders decode: %w", err)
	}

	var outbox []coresync.OutboxMutation
	if len(plain.OutboxJSON) > 0 {
		if err := json.Unmarshal(plain.OutboxJSON, &outbox); err != nil {
			return nil, nil, nil, fmt.Errorf("cache outbox decode: %w", err)
		}
	}

	// Zero plain JSON fields after decode.
	clear(plain.ItemsJSON)
	clear(plain.FoldersJSON)
	clear(plain.OutboxJSON)

	return items, folders, outbox, nil
}

// Lock transitions the service from unlocked to locked.
func (s *Service) Lock(ctx context.Context) error {
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
func (s *Service) UpdateConfig(ctx context.Context, cfg *config.Config) error {
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
func (s *Service) Shutdown(ctx context.Context) error {
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

// ensureUnlocked returns ErrLocked if the service is not in the unlocked state.
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
func (s *Service) appendOutboxLocked(kind coresync.MutationKind, itemID string, payload []byte) coresync.OutboxMutation {
	s.outboxSeq++
	m := coresync.OutboxMutation{
		ID:        fmt.Sprintf("m-%d-%d", s.now().UnixNano(), s.outboxSeq),
		Kind:      kind,
		ItemID:    itemID,
		CreatedAt: s.now(),
		Payload:   payload,
	}
	s.outbox = append(s.outbox, m)
	s.saveCacheAsyncLocked()
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
func (s *Service) saveCacheAsyncLocked() {
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
	logger := s.deps.Logger
	accountHash := s.accountHashLocked()

	if len(key) == 0 {
		return
	}

	s.saveWG.Add(1)
	go func() {
		defer s.saveWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if outboxStore != nil {
			if err := outboxStore.Save(ctx, key, outboxSnap); err != nil && logger != nil {
				logger.Error("outbox save failed", "error", err)
			}
		}

		if cacheStore != nil && box != nil && len(salt) > 0 {
			if err := saveEncryptedSnapshot(ctx, cacheStore, box, key, salt, accountHash, itemsSnap, foldersSnap, outboxSnap); err != nil && logger != nil {
				logger.Error("cache save failed", "error", err)
			}
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
		if s.deps.Logger != nil {
			s.deps.Logger.Error("app: save refreshed token bundle failed", "error", saveErr)
		}
	}

	return updated, nil
}

// AuthStatus reports the session authentication state for the given email.
func (s *Service) AuthStatus(ctx context.Context, email string) (session.AuthStatus, error) {
	if err := s.checkCredentialsAvailable(ctx); err != nil {
		return session.KeyringUnavailable, err
	}

	ref := s.accountRef(email)

	// Load token bundle; if not found the user is unauthenticated.
	_, err := s.deps.Credentials.LoadTokenBundle(ctx, ref)
	if err != nil {
		if errors.Is(err, cerrors.ErrNotFound) {
			return session.Unauthenticated, nil
		}
		return session.KeyringUnavailable, fmt.Errorf("app: load token bundle: %w", err)
	}

	// Load unlock envelope; if not found the vault is locked.
	env, err := s.deps.Credentials.LoadUnlockEnvelope(ctx, ref)
	if err != nil {
		if errors.Is(err, cerrors.ErrNotFound) {
			return session.LoggedInLocked, nil
		}
		return session.KeyringUnavailable, fmt.Errorf("app: load unlock envelope: %w", err)
	}

	// BootID dependency is required to validate the envelope.
	if s.deps.BootID == nil {
		return session.LoggedInLocked, nil
	}

	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil {
		return session.LoggedInLocked, fmt.Errorf("app: boot id: %w", err)
	}

	if err := env.Validate(ref, bootID, s.now()); err != nil {
		// Envelope validation failed: account mismatch, boot changed,
		// expired, or PIN backoff.
		return session.LoggedInLocked, nil
	}

	return session.LoggedInUnlockAvailable, nil
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
func (s *Service) Create(ctx context.Context, item vault.Item) (vault.Item, error) {
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
				if s.deps.Logger != nil {
					s.deps.Logger.Warn("remote create succeeded but service locked before local update", "item_id", remoteItem.ID)
				}
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
	s.appendOutboxLocked(coresync.MutationCreate, item.ID, payload)

	s.items = append(s.items, item)
	s.rebuildIndexLocked()
	s.emit(MutationPending, "item queued for creation")
	return item, nil
}

// Update updates an existing vault item. Tries remote first, falls back to
// local pending mutation.
func (s *Service) Update(ctx context.Context, id string, item vault.Item) (vault.Item, error) {
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
				if s.deps.Logger != nil {
					s.deps.Logger.Warn("remote update succeeded but service locked before local update", "item_id", id)
				}
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
	s.appendOutboxLocked(coresync.MutationUpdate, id, payload)

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
func (s *Service) Trash(ctx context.Context, id string) error {
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
				if s.deps.Logger != nil {
					s.deps.Logger.Warn("remote trash succeeded but service locked before local update", "item_id", id)
				}
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
	s.appendOutboxLocked(coresync.MutationTrash, id, payload)

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
func (s *Service) Restore(ctx context.Context, id string) (vault.Item, error) {
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
				if s.deps.Logger != nil {
					s.deps.Logger.Warn("remote restore succeeded but service locked before local update", "item_id", id)
				}
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
	s.appendOutboxLocked(coresync.MutationRestore, id, payload)

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
func (s *Service) Delete(ctx context.Context, id string) error {
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
				if s.deps.Logger != nil {
					s.deps.Logger.Warn("remote delete succeeded but service locked before local update", "item_id", id)
				}
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
	s.appendOutboxLocked(coresync.MutationDelete, id, payload)

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
func (s *Service) ListAttachments(ctx context.Context, itemID string) ([]vault.Attachment, error) {
	return nil, cerrors.ErrUnsupported
}

// DownloadAttachment is not yet supported.
func (s *Service) DownloadAttachment(ctx context.Context, itemID, attachmentID string, dst io.Writer) error {
	return cerrors.ErrUnsupported
}

// UploadAttachment is not yet supported.
func (s *Service) UploadAttachment(ctx context.Context, itemID, fileName string, size int64, src io.Reader) (vault.Attachment, error) {
	return vault.Attachment{}, cerrors.ErrUnsupported
}

// DeleteAttachment is not yet supported.
func (s *Service) DeleteAttachment(ctx context.Context, itemID, attachmentID string) error {
	return cerrors.ErrUnsupported
}

// ResolveConflict resolves a sync conflict by applying the given resolution.
func (s *Service) ResolveConflict(ctx context.Context, conflictID string, resolution coresync.ConflictResolution) error {
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
	s.saveCacheAsyncLocked()
	s.emit(SyncUpdated, "conflict resolved")
	return nil
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

// replayOutbox replays outbox mutations against the remote. It must be called
// OUTSIDE of s.mu to avoid deadlocks with Remote methods.
func (s *Service) replayOutbox(ctx context.Context, outbox []coresync.OutboxMutation) error {
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
	s.emit(SyncChecking, "checking remote revision")

	if s.deps.Remote == nil {
		return
	}

	rev, err := s.deps.Remote.Revision(ctx)
	if err != nil {
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
		s.emit(SyncFailed, fmt.Sprintf("remote sync failed: %v", err))
		return
	}

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
		s.mu.Unlock()
		return
	}

	// Detect conflicts.
	conflicts := coresync.DetectConflicts(outboxSnapshot, remoteChanges)
	if len(conflicts) > 0 {
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
			s.emit(SyncFailed, fmt.Sprintf("outbox replay failed: %v", err))
			// Do NOT clear outbox or install remote state on replay failure.
			return
		}

		// Re-fetch remote state after successful replay.
		remoteItems, remoteFolders, remoteRev, err = s.deps.Remote.Sync(ctx)
		if err != nil {
			s.emit(SyncFailed, fmt.Sprintf("post-replay sync failed: %v", err))
			// Keep outbox intact.
			return
		}
	}

	// Install final remote state under lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx.Err() != nil {
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
	s.saveCacheAsyncLocked()
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
