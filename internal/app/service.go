package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/cache"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	cerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
)

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

// Unlock transitions the service from locked to unlocked.
func (s *Service) Unlock(ctx context.Context, email, password string) (retErr error) {
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
		if err := s.deps.Remote.Login(ctx, email, password); err != nil {
			s.mu.Lock()
			s.state = auth.LockStateLocked
			s.mu.Unlock()
			return fmt.Errorf("app: login failed: %w", err)
		}
	}

	// Derive a cache key from the password.
	key := sha256.Sum256([]byte(password))

	// Load cache data (items, folders, outbox) without installing state.
	loadedItems, loadedFolders, outboxMutations, loaded, err := s.loadCacheData(ctx, key[:])
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
		s.index = vault.BuildIndex(loadedItems)
	}
	// Copy cache key for outbox persistence.
	s.cacheKey = make([]byte, len(key[:]))
	copy(s.cacheKey, key[:])
	s.state = auth.LockStateUnlocked

	if loaded {
		s.emit(IndexReady, "search index ready")
	}

	// Start background sync worker.
	ctx, cancel := context.WithCancel(ctx)
	s.cancelWorkers = cancel
	s.emit(Unlocking, "starting sync worker")

	s.startMinimalSyncWorker(ctx)

	return nil
}

// loadCacheData loads and decrypts a cached vault snapshot, returning the
// items, folders, and outbox mutations. It does NOT install state on the
// service — that is the caller's responsibility.
func (s *Service) loadCacheData(ctx context.Context, key []byte) (items []vault.Item, folders []vault.Folder, outbox []coresync.OutboxMutation, loaded bool, err error) {
	snap, err := s.deps.Cache.Load(ctx)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("cache load: %w", err)
	}

	if err := cache.ValidateSnapshot(snap); err != nil {
		return nil, nil, nil, false, fmt.Errorf("cache validation: %w", err)
	}

	var ciphertext []byte
	if s.deps.SecretBox != nil {
		ciphertext, err = s.deps.SecretBox.Open(snap.VaultCiphertext, key)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("cache decrypt: %w", err)
		}
	} else {
		ciphertext = snap.VaultCiphertext
	}

	var plain cache.PlainSnapshot
	if err := json.Unmarshal(ciphertext, &plain); err != nil {
		return nil, nil, nil, false, fmt.Errorf("cache decode: %w", err)
	}

	if err := json.Unmarshal(plain.ItemsJSON, &items); err != nil {
		return nil, nil, nil, false, fmt.Errorf("cache items decode: %w", err)
	}

	if err := json.Unmarshal(plain.FoldersJSON, &folders); err != nil {
		return nil, nil, nil, false, fmt.Errorf("cache folders decode: %w", err)
	}

	// Decode outbox from PlainSnapshot.OutboxJSON.
	if len(plain.OutboxJSON) > 0 {
		var cachedOutbox []coresync.OutboxMutation
		if err := json.Unmarshal(plain.OutboxJSON, &cachedOutbox); err != nil {
			return nil, nil, nil, false, fmt.Errorf("cache outbox decode: %w", err)
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

	return items, folders, outbox, true, nil
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

	// Clear cache key.
	s.cacheKey = nil

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
func (s *Service) Search(ctx context.Context, query string, limit int) ([]vault.ScoredItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != auth.LockStateUnlocked {
		return nil, cerrors.ErrLocked
	}

	if s.index == nil {
		return nil, nil
	}

	return s.index.Search(query, limit), nil
}

// Items returns a copy of all vault items. Returns ErrLocked if not unlocked.
func (s *Service) Items(ctx context.Context) ([]vault.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != auth.LockStateUnlocked {
		return nil, cerrors.ErrLocked
	}

	items := make([]vault.Item, len(s.items))
	copy(items, s.items)
	return items, nil
}

// Get returns a single vault item by ID.
func (s *Service) Get(ctx context.Context, id string) (vault.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != auth.LockStateUnlocked {
		return vault.Item{}, cerrors.ErrLocked
	}

	for _, item := range s.items {
		if item.ID == id {
			return item, nil
		}
	}

	return vault.Item{}, cerrors.ErrNotFound
}

// Config returns the current configuration.
func (s *Service) Config() *config.Config {
	return s.cfg
}

// Events returns a read-only channel of domain events.
func (s *Service) Events() <-chan Event {
	return s.events
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
	s.cacheKey = nil
	s.state = auth.LockStateLocked
	s.mu.Unlock()

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

// rebuildIndexLocked rebuilds the search index from the current items slice.
// The caller must hold s.mu.
func (s *Service) rebuildIndexLocked() {
	s.index = vault.BuildIndex(s.items)
}

// appendOutboxLocked appends a mutation to the outbox and returns it.
// The caller must hold s.mu.
func (s *Service) appendOutboxLocked(kind coresync.MutationKind, itemID string, payload []byte) coresync.OutboxMutation {
	m := coresync.OutboxMutation{
		ID:        fmt.Sprintf("m-%d", s.now().UnixNano()),
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

// saveCacheAsyncLocked snapshots the outbox and cacheKey, then
// asynchronously persists to deps.Outbox if available.
// The caller MUST hold s.mu.
func (s *Service) saveCacheAsyncLocked() {
	key := make([]byte, len(s.cacheKey))
	copy(key, s.cacheKey)
	outboxSnap := make([]coresync.OutboxMutation, len(s.outbox))
	copy(outboxSnap, s.outbox)
	store := s.deps.Outbox

	if store == nil || len(key) == 0 {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = store.Save(ctx, key, outboxSnap)
	}()
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
		item.ID = fmt.Sprintf("local-%d", s.now().UnixNano())
	}
	item.SyncStatus = vault.SyncStatusPending
	item.RevisionDate = s.now()

	payload, _ := json.Marshal(item)
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

	payload, _ := json.Marshal(item)
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

	payload, _ := json.Marshal(map[string]string{"id": id})
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

	payload, _ := json.Marshal(map[string]string{"id": id})
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

	payload, _ := json.Marshal(map[string]string{"id": id})
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
			dup.ID = fmt.Sprintf("local-%d", s.now().UnixNano())
			dup.SyncStatus = vault.SyncStatusPending
			dup.ConflictID = ""
			s.items = append(s.items, dup)

			payload, _ := json.Marshal(dup)
			s.appendOutboxLocked(coresync.MutationCreate, dup.ID, payload)

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

// startMinimalSyncWorker starts a background goroutine that runs syncOnce.
func (s *Service) startMinimalSyncWorker(ctx context.Context) {
	go func() {
		s.syncOnce(ctx)
	}()
}
