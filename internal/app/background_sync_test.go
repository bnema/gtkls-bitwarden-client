package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/session"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

func TestSetBackgroundSyncSuspendedUnlocked(t *testing.T) {
	svc := NewService(Deps{Config: coreconfig.Default()})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.backgroundSyncMode = backgroundSyncCacheOnly
	svc.mu.Unlock()

	require.NoError(t, svc.SetBackgroundSyncSuspended(context.Background(), true))
	svc.mu.Lock()
	require.True(t, svc.backgroundSyncSuspended)
	svc.mu.Unlock()

	require.NoError(t, svc.SetBackgroundSyncSuspended(context.Background(), false))
	svc.mu.Lock()
	require.False(t, svc.backgroundSyncSuspended)
	svc.mu.Unlock()
}

func TestSetBackgroundSyncSuspendedLockedIsNoOp(t *testing.T) {
	svc := NewService(Deps{Config: coreconfig.Default()})

	require.NoError(t, svc.SetBackgroundSyncSuspended(context.Background(), true))
	svc.mu.Lock()
	require.False(t, svc.backgroundSyncSuspended)
	svc.mu.Unlock()
}

func TestUnlockWithPINConfiguresCacheOnlyWorkerStateWhenEnabled(t *testing.T) {
	email := "user@example.com"
	pin := "1234"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-abc"

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email
	cfg.Security.BackgroundSync.Enabled = true
	cfg.Security.BackgroundSync.Interval = 10 * time.Minute

	envelope := session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		AccountID:      "acct-1",
		BootID:         bootID,
		ExpiresAt:      time.Now().Add(time.Hour),
		PINMaxFailures: 5,
	}
	material := session.UnlockMaterial{CacheKey: []byte("cache-key"), UserKey: []byte("user-key")}

	svc := NewService(Deps{
		Config: cfg,
		Remote: &fakeRemote{},
		Credentials: &fakeCredentialStore{
			tokenBundle: session.TokenBundle{
				AccountID:    "acct-1",
				Email:        ref.Email,
				ServerURL:    ref.ServerURL,
				AccessToken:  []byte("at"),
				RefreshToken: []byte("rt"),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			envelope: envelope,
		},
		BootID: &fakeBootID{id: bootID},
		PINEnvelope: &fakePINEnvelope{
			result:       envelope.Clone(),
			openMaterial: material,
			openUpdated:  envelope.Clone(),
		},
	})

	require.NoError(t, svc.UnlockWithPIN(context.Background(), email, pin))

	svc.mu.Lock()
	require.Equal(t, backgroundSyncCacheOnly, svc.backgroundSyncMode)
	require.NotNil(t, svc.cancelWorkers)
	svc.mu.Unlock()

	require.NoError(t, svc.SoftLock(context.Background()))
}

func TestStartBackgroundSyncWorkerDoesNotMutateStateOnLockedService(t *testing.T) {
	// Regression: startBackgroundSyncWorker must not write backgroundSyncMode
	// or backgroundSyncSuspended on a locked service. If SoftLock/Shutdown
	// runs between the unlock path dropping s.mu and calling
	// startBackgroundSyncWorker, the worker startup would otherwise
	// overwrite the mode on an already-locked service and launch a
	// goroutine with an already-canceled context.
	cfg := coreconfig.Default()
	svc := NewService(Deps{Config: cfg})

	// Service starts locked with backgroundSyncDisabled (zero value).
	svc.mu.Lock()
	require.Equal(t, auth.LockStateLocked, svc.state)
	require.Equal(t, backgroundSyncDisabled, svc.backgroundSyncMode)
	require.False(t, svc.backgroundSyncSuspended)
	svc.mu.Unlock()

	// Simulate the race: a canceled context arrives when SoftLock/Shutdown
	// already ran and canceled the workers.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	svc.startBackgroundSyncWorker(canceledCtx, backgroundSyncCacheOnly)

	// State must not have been overwritten.
	svc.mu.Lock()
	require.Equal(t, backgroundSyncDisabled, svc.backgroundSyncMode,
		"backgroundSyncMode must stay disabled on a locked service")
	require.False(t, svc.backgroundSyncSuspended,
		"backgroundSyncSuspended must stay false on a locked service")
	svc.mu.Unlock()
}

func TestUnlockWithPINLeavesWorkerDisabledWhenBackgroundSyncDisabled(t *testing.T) {
	email := "user@example.com"
	pin := "1234"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-abc"

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email
	cfg.Security.BackgroundSync.Enabled = false

	envelope := session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		AccountID:      "acct-1",
		BootID:         bootID,
		ExpiresAt:      time.Now().Add(time.Hour),
		PINMaxFailures: 5,
	}
	material := session.UnlockMaterial{CacheKey: []byte("cache-key"), UserKey: []byte("user-key")}

	svc := NewService(Deps{
		Config: cfg,
		Remote: &fakeRemote{},
		Credentials: &fakeCredentialStore{
			tokenBundle: session.TokenBundle{
				AccountID:    "acct-1",
				Email:        ref.Email,
				ServerURL:    ref.ServerURL,
				AccessToken:  []byte("at"),
				RefreshToken: []byte("rt"),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			envelope: envelope,
		},
		BootID: &fakeBootID{id: bootID},
		PINEnvelope: &fakePINEnvelope{
			result:       envelope.Clone(),
			openMaterial: material,
			openUpdated:  envelope.Clone(),
		},
	})

	require.NoError(t, svc.UnlockWithPIN(context.Background(), email, pin))

	svc.mu.Lock()
	require.Equal(t, backgroundSyncDisabled, svc.backgroundSyncMode)
	require.Nil(t, svc.cancelWorkers)
	svc.mu.Unlock()
}

func TestUnlockLeavesResidentWorkerDisabledWhenBackgroundSyncDisabled(t *testing.T) {
	cfg := coreconfig.Default()
	cfg.Security.BackgroundSync.Enabled = false

	svc := NewService(Deps{Config: cfg, Remote: &fakeRemote{}})
	require.NoError(t, svc.Unlock(context.Background(), "user@example.com", "master-password"))

	svc.mu.Lock()
	require.Equal(t, backgroundSyncDisabled, svc.backgroundSyncMode)
	require.Nil(t, svc.cancelWorkers)
	svc.mu.Unlock()
}

func TestSyncOnceCacheOnlyRefreshesEncryptedCacheWithoutResidentState(t *testing.T) {
	cacheKey := []byte("test-cache-key-32-bytes-long!")
	cachedItem := vault.Item{ID: "item-1", Name: "GitHub", Type: vault.ItemTypeLogin}
	refreshedItem := vault.Item{ID: "item-1", Name: "GitHub Refreshed", Type: vault.ItemTypeLogin, RevisionDate: time.Now()}

	snap := buildCacheSnapshotWithKey(t, cacheKey, []vault.Item{cachedItem}, nil)
	svc := NewService(Deps{
		Config:    coreconfig.Default(),
		Remote:    &fakeRemote{revisionRev: "rev-2", syncItems: []vault.Item{refreshedItem}, syncRev: "rev-2"},
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], cacheKey...)
	svc.backgroundSyncMode = backgroundSyncCacheOnly
	svc.mu.Unlock()

	svc.syncOnceCacheOnly(context.Background())

	items, folders, outbox, err := svc.loadCachedVaultWithKey(context.Background(), cacheKey)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, refreshedItem.Name, items[0].Name)
	require.Empty(t, folders)
	require.Empty(t, outbox)

	svc.mu.Lock()
	require.Nil(t, svc.items)
	require.Nil(t, svc.folders)
	require.Nil(t, svc.index)
	svc.mu.Unlock()
}

func TestSyncOnceByModeSkipsSuspendedCacheOnlyWorker(t *testing.T) {
	cacheKey := []byte("test-cache-key-32-bytes-long!")
	cachedItem := vault.Item{ID: "item-1", Name: "Cached", Type: vault.ItemTypeLogin}
	remote := &fakeRemote{
		revisionRev: "rev-2",
		syncItems:   []vault.Item{{ID: "item-1", Name: "Remote", Type: vault.ItemTypeLogin, RevisionDate: time.Now()}},
		syncRev:     "rev-2",
	}
	snap := buildCacheSnapshotWithKey(t, cacheKey, []vault.Item{cachedItem}, nil)

	svc := NewService(Deps{
		Config:    coreconfig.Default(),
		Remote:    remote,
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], cacheKey...)
	svc.backgroundSyncMode = backgroundSyncCacheOnly
	svc.backgroundSyncSuspended = true
	svc.mu.Unlock()

	svc.syncOnceByMode(context.Background(), backgroundSyncCacheOnly)

	require.Equal(t, int32(0), remote.syncCalled.Load())
}

func TestSyncOnceCacheOnlyMarksConflictsInEncryptedCache(t *testing.T) {
	cacheKey := []byte("test-cache-key-32-bytes-long!")
	localItem := vault.Item{
		ID:           "item-1",
		Name:         "Local Version",
		Type:         vault.ItemTypeLogin,
		RevisionDate: time.Now().Add(-time.Hour),
		SyncStatus:   vault.SyncStatusPending,
	}
	pendingUpdate := coresync.OutboxMutation{
		ID:        "m1",
		Kind:      coresync.MutationUpdate,
		ItemID:    "item-1",
		CreatedAt: time.Now().Add(-30 * time.Minute),
		Payload:   []byte(`{"name":"Local Version"}`),
	}
	remoteItem := vault.Item{
		ID:           "item-1",
		Name:         "Remote Version",
		Type:         vault.ItemTypeLogin,
		RevisionDate: time.Now(),
	}

	snap := buildCacheSnapshotWithKeyAndOutbox(t, cacheKey, []vault.Item{localItem}, nil, []coresync.OutboxMutation{pendingUpdate})
	svc := NewService(Deps{
		Config:    coreconfig.Default(),
		Remote:    &fakeRemote{revisionRev: "rev-2", syncItems: []vault.Item{remoteItem}, syncRev: "rev-2"},
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], cacheKey...)
	svc.backgroundSyncMode = backgroundSyncCacheOnly
	svc.mu.Unlock()

	svc.syncOnceCacheOnly(context.Background())

	items, folders, outbox, err := svc.loadCachedVaultWithKey(context.Background(), cacheKey)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Empty(t, folders)
	require.Len(t, outbox, 1)
	require.Equal(t, vault.SyncStatusConflict, items[0].SyncStatus)
	require.NotEmpty(t, items[0].ConflictID)
	require.Equal(t, pendingUpdate.ID, outbox[0].ID)
	require.Equal(t, pendingUpdate.ItemID, outbox[0].ItemID)

	persistedConflicts, err := svc.loadCachedConflictsWithKey(context.Background(), cacheKey)
	require.NoError(t, err)
	require.Len(t, persistedConflicts, 1)
	require.Equal(t, localItem.ID, persistedConflicts[0].ItemID)
	require.Equal(t, items[0].ConflictID, persistedConflicts[0].ID)

	svc.mu.Lock()
	require.Len(t, svc.conflicts, 1)
	require.Equal(t, localItem.ID, svc.conflicts[0].ItemID)
	require.Empty(t, svc.pendingRemoteItems)
	require.Empty(t, svc.pendingRemoteFolders)
	svc.mu.Unlock()
}

func TestSyncOnceCacheOnlyReplaysOutboxBeforeClearingEncryptedCache(t *testing.T) {
	cacheKey := []byte("test-cache-key-32-bytes-long!")
	pendingItem := vault.Item{ID: "pending-1", Name: "Pending Create", Type: vault.ItemTypeLogin}
	payload, err := json.Marshal(pendingItem)
	require.NoError(t, err)

	createCalled := make(chan struct{}, 1)
	snap := buildCacheSnapshotWithKeyAndOutbox(t, cacheKey, nil, nil, []coresync.OutboxMutation{{
		ID:        "m1",
		Kind:      coresync.MutationCreate,
		ItemID:    pendingItem.ID,
		CreatedAt: time.Now().Add(-time.Minute),
		Payload:   payload,
	}})
	svc := NewService(Deps{
		Config: coreconfig.Default(),
		Remote: &fakeRemote{
			revisionRev: "rev-2",
			syncItems:   []vault.Item{{ID: "remote-1", Name: "Remote Item", Type: vault.ItemTypeLogin, RevisionDate: time.Now()}},
			syncRev:     "rev-2",
			onCreate: func(_ context.Context, item vault.Item) (vault.Item, error) {
				require.Equal(t, pendingItem.ID, item.ID)
				createCalled <- struct{}{}
				return vault.Item{ID: "remote-pending-1", Name: item.Name, Type: item.Type, RevisionDate: time.Now()}, nil
			},
		},
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], cacheKey...)
	svc.backgroundSyncMode = backgroundSyncCacheOnly
	svc.mu.Unlock()

	svc.syncOnceCacheOnly(context.Background())

	_, _, outbox, err := svc.loadCachedVaultWithKey(context.Background(), cacheKey)
	require.NoError(t, err)
	require.Empty(t, outbox, "encrypted cache outbox should be cleared only after replay succeeds")

	select {
	case <-createCalled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("remote.Create was not called before cache-only sync cleared the encrypted outbox")
	}
}

func TestSoftLockResetsBackgroundSyncState(t *testing.T) {
	svc := NewService(Deps{Config: coreconfig.Default(), Remote: &fakeRemote{}})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.backgroundSyncMode = backgroundSyncCacheOnly
	svc.backgroundSyncSuspended = true
	svc.cancelWorkers = func() {}
	svc.mu.Unlock()

	require.NoError(t, svc.SoftLock(context.Background()))

	svc.mu.Lock()
	require.Equal(t, backgroundSyncDisabled, svc.backgroundSyncMode)
	require.False(t, svc.backgroundSyncSuspended)
	require.Nil(t, svc.cancelWorkers)
	svc.mu.Unlock()
}

func TestSyncOnceResidentStillInstallsResidentState(t *testing.T) {
	remote := &fakeRemote{
		revisionRev: "rev-1",
		syncItems:   []vault.Item{{ID: "item-1", Name: "GitHub", Type: vault.ItemTypeLogin, RevisionDate: time.Now()}},
		syncRev:     "rev-1",
	}
	svc := NewService(Deps{Config: coreconfig.Default(), Remote: remote})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.backgroundSyncMode = backgroundSyncResident
	svc.mu.Unlock()

	svc.syncOnceResident(context.Background())

	svc.mu.Lock()
	require.Len(t, svc.items, 1)
	require.Equal(t, "GitHub", svc.items[0].Name)
	require.Nil(t, svc.index)
	svc.mu.Unlock()
}
