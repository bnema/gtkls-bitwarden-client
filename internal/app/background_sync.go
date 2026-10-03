package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
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

func (s *Service) SetBackgroundSyncSuspended(ctx context.Context, suspended bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != auth.LockStateUnlocked || s.backgroundSyncMode == backgroundSyncDisabled {
		return nil
	}

	s.backgroundSyncSuspended = suspended
	return nil
}

// SyncNow performs one immediate sync using the current unlocked session mode.
// Resident sessions refresh resident state; cache-only sessions refresh the
// encrypted cache without installing plaintext resident items.
func (s *Service) SyncNow(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	cacheOnly := s.backgroundSyncMode == backgroundSyncCacheOnly || (s.items == nil && s.folders == nil && s.outbox == nil && len(s.cacheKey) > 0)
	s.mu.Unlock()

	if cacheOnly {
		return s.syncOnceCacheOnly(ctx)
	}
	return s.syncOnce(ctx)
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

	vc := s.vaultCache()
	if err := vc.Save(cleanupCtx, key, accountHash, snap); err != nil {
		if errors.Is(err, errNoCacheSalt) {
			return fmt.Errorf("save cache: %w", err)
		}
		return err
	}
	if err := vc.SaveOutbox(cleanupCtx, key, snap.Outbox); err != nil {
		return fmt.Errorf("save outbox: %w", err)
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
	_ = s.syncOnce(ctx)
}

func (s *Service) syncOnceCacheOnly(ctx context.Context) error {
	if s.deps.Remote == nil || s.deps.Cache == nil || s.deps.SecretBox == nil {
		return nil
	}

	s.emit(SyncChecking, "checking remote revision")

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil || s.backgroundSyncSuspended {
		s.mu.Unlock()
		return err
	}
	expectedSeq := s.saveSeq
	key := append([]byte(nil), s.cacheKey...)
	s.mu.Unlock()
	defer clear(key)

	if len(key) == 0 {
		return nil
	}

	snap, err := s.vaultCache().Open(ctx, key)
	if err != nil {
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return err
	}
	if len(snap.Salt) == 0 {
		err = fmt.Errorf("cache save: no cache salt available")
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return err
	}

	remoteItems, remoteFolders, remoteRev, err := s.deps.Remote.Sync(ctx)
	if err != nil {
		s.emit(SyncFailed, cerrors.ShortMessage(err))
		return err
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
			return err
		}

		s.emitCount(ConflictDetected, fmt.Sprintf("%d conflict(s) detected", len(conflicts)), len(conflicts))
		return nil
	}

	if len(snap.Outbox) > 0 {
		if err := s.replayOutbox(ctx, snap.Outbox); err != nil {
			s.emit(SyncFailed, cerrors.ShortMessage(err))
			return err
		}

		remoteItems, remoteFolders, remoteRev, err = s.deps.Remote.Sync(ctx)
		if err != nil {
			s.emit(SyncFailed, cerrors.ShortMessage(err))
			return err
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
		return err
	}

	s.mu.Lock()
	s.conflicts = nil
	s.pendingRemoteItems = nil
	s.pendingRemoteFolders = nil
	s.mu.Unlock()

	s.emit(SyncUpdated, fmt.Sprintf("sync complete (rev: %s)", remoteRev))
	return nil
}
