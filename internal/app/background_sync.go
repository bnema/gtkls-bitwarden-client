package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/cache"
	cerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

type backgroundSyncMode int

const (
	backgroundSyncDisabled backgroundSyncMode = iota
	backgroundSyncResident
	backgroundSyncCacheOnly
)

type decryptedCacheSnapshot struct {
	Salt      []byte
	Items     []vault.Item
	Folders   []vault.Folder
	Outbox    []coresync.OutboxMutation
	Conflicts []coresync.Conflict
}

func (s *Service) SetBackgroundSyncSuspended(ctx context.Context, suspended bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != auth.LockStateUnlocked || s.backgroundSyncMode == backgroundSyncDisabled {
		return nil
	}

	s.backgroundSyncSuspended = suspended
	return nil
}

func (s *Service) backgroundSyncEnabledLocked() bool {
	return s.cfg != nil && s.cfg.Security.BackgroundSync.Enabled
}

func (s *Service) startBackgroundSyncWorker(ctx context.Context, mode backgroundSyncMode) {
	go func() {
		s.syncOnceByMode(ctx, mode)

		ticker := time.NewTicker(s.syncInterval())
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.syncOnceByMode(ctx, mode)
			}
		}
	}()
}

func (s *Service) loadDecryptedCacheSnapshot(ctx context.Context, key []byte) (decryptedCacheSnapshot, error) {
	var snap decryptedCacheSnapshot

	if s.deps.Cache == nil || s.deps.SecretBox == nil || len(key) == 0 {
		return snap, nil
	}

	cached, err := s.deps.Cache.Load(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return snap, nil
		}
		return snap, fmt.Errorf("cache load: %w", err)
	}

	if cached.Version == 0 && cached.AccountHash == "" && len(cached.VaultCiphertext) == 0 {
		return snap, nil
	}

	if err := cache.ValidateSnapshot(cached); err != nil {
		return snap, fmt.Errorf("cache validation: %w", err)
	}

	items, folders, outbox, err := s.loadCachedVaultWithKey(ctx, key)
	if err != nil {
		return snap, err
	}
	conflicts, err := s.loadCachedConflictsWithKey(ctx, key)
	if err != nil {
		return snap, err
	}

	snap.Salt = append([]byte(nil), cached.CacheKeySalt...)
	snap.Items = append([]vault.Item(nil), items...)
	snap.Folders = append([]vault.Folder(nil), folders...)
	snap.Outbox = append([]coresync.OutboxMutation(nil), outbox...)
	snap.Conflicts = append([]coresync.Conflict(nil), conflicts...)
	return snap, nil
}

func (s *Service) saveExplicitCacheSnapshot(ctx context.Context, key []byte, snap decryptedCacheSnapshot, expectedSeq uint64) error {
	if len(key) == 0 {
		return nil
	}
	if s.deps.Cache == nil || s.deps.SecretBox == nil {
		return nil
	}

	s.cacheSaveMu.Lock()
	defer s.cacheSaveMu.Unlock()

	s.mu.Lock()
	if s.saveSeq != expectedSeq {
		s.mu.Unlock()
		return fmt.Errorf("save cache: stale snapshot")
	}
	s.saveSeq++
	accountHash := s.accountHashLocked()
	s.mu.Unlock()

	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	salt := append([]byte(nil), snap.Salt...)
	if len(salt) == 0 {
		existing, err := s.deps.Cache.Load(cleanupCtx)
		if err == nil && len(existing.CacheKeySalt) > 0 {
			salt = append([]byte(nil), existing.CacheKeySalt...)
		}
	}
	if len(salt) == 0 {
		return fmt.Errorf("save cache: no cache salt available")
	}

	if err := saveEncryptedSnapshot(cleanupCtx, s.deps.Cache, s.deps.SecretBox, key, salt, accountHash, snap.Items, snap.Folders, snap.Outbox, snap.Conflicts); err != nil {
		return err
	}

	if s.deps.Outbox != nil {
		if err := s.deps.Outbox.Save(cleanupCtx, key, snap.Outbox); err != nil {
			return fmt.Errorf("save outbox: %w", err)
		}
	}

	return nil
}

func (s *Service) syncOnceByMode(ctx context.Context, mode backgroundSyncMode) {
	s.mu.Lock()
	locked := s.state != auth.LockStateUnlocked
	suspended := s.backgroundSyncSuspended
	backgroundSyncEnabled := s.backgroundSyncEnabledLocked()
	s.mu.Unlock()

	if locked || suspended || !backgroundSyncEnabled {
		return
	}

	switch mode {
	case backgroundSyncResident:
		s.syncOnceResident(ctx)
	case backgroundSyncCacheOnly:
		s.syncOnceCacheOnly(ctx)
	}
}

func (s *Service) syncOnceResident(ctx context.Context) {
	s.syncOnce(ctx)
}

func (s *Service) syncOnceCacheOnly(ctx context.Context) {
	if s.deps.Remote == nil || s.deps.Cache == nil || s.deps.SecretBox == nil {
		return
	}

	s.emit(SyncChecking, "checking remote revision")

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil || s.backgroundSyncSuspended {
		s.mu.Unlock()
		return
	}
	expectedSeq := s.saveSeq
	key := append([]byte(nil), s.cacheKey...)
	s.mu.Unlock()
	defer clear(key)

	if len(key) == 0 {
		return
	}

	snap, err := s.loadDecryptedCacheSnapshot(ctx, key)
	if err != nil {
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return
	}
	if len(snap.Salt) == 0 {
		err = fmt.Errorf("cache save: no cache salt available")
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return
	}

	remoteItems, remoteFolders, remoteRev, err := s.deps.Remote.Sync(ctx)
	if err != nil {
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return
	}

	remoteChanges := make([]coresync.RemoteChange, 0, len(remoteItems))
	for _, remoteItem := range remoteItems {
		remoteChanges = append(remoteChanges, coresync.RemoteChange{
			ItemID:   remoteItem.ID,
			Revision: remoteItem.RevisionDate.Format(time.RFC3339),
			Deleted:  remoteItem.Deleted,
		})
	}

	conflicts := coresync.DetectConflicts(snap.Outbox, remoteChanges)
	if len(conflicts) > 0 {
		s.mu.Lock()
		s.conflicts = append([]coresync.Conflict(nil), conflicts...)
		s.pendingRemoteItems = nil
		s.pendingRemoteFolders = nil
		s.mu.Unlock()

		snap.Conflicts = append([]coresync.Conflict(nil), conflicts...)
		for _, conflict := range conflicts {
			for i := range snap.Items {
				if snap.Items[i].ID == conflict.ItemID {
					snap.Items[i].SyncStatus = vault.SyncStatusConflict
					snap.Items[i].ConflictID = conflict.ID
					break
				}
			}
		}

		if err := s.saveExplicitCacheSnapshot(ctx, key, snap, expectedSeq); err != nil {
			s.emit(SyncFailed, cerrors.ShortMessage(err))
			return
		}

		s.emitCount(ConflictDetected, fmt.Sprintf("%d conflict(s) detected", len(conflicts)), len(conflicts))
		return
	}

	if len(snap.Outbox) > 0 {
		if err := s.replayOutbox(ctx, snap.Outbox); err != nil {
			s.emit(SyncFailed, cerrors.ShortMessage(err))
			return
		}

		remoteItems, remoteFolders, remoteRev, err = s.deps.Remote.Sync(ctx)
		if err != nil {
			s.emit(SyncFailed, cerrors.ShortMessage(err))
			return
		}
	}

	for i := range remoteItems {
		remoteItems[i].SyncStatus = vault.SyncStatusSynced
	}

	snap.Items = append(snap.Items[:0], remoteItems...)
	snap.Folders = append(snap.Folders[:0], remoteFolders...)
	snap.Outbox = nil
	snap.Conflicts = nil
	if err := s.saveExplicitCacheSnapshot(ctx, key, snap, expectedSeq); err != nil {
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return
	}

	s.mu.Lock()
	s.conflicts = nil
	s.pendingRemoteItems = nil
	s.pendingRemoteFolders = nil
	s.mu.Unlock()

	s.emit(SyncUpdated, fmt.Sprintf("sync complete (rev: %s)", remoteRev))
}
