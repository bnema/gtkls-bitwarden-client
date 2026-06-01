package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/cache/crypto"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/cache/file"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/cache"
	coreerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// ---------------------------------------------------------------------------
// Test 1: Offline unlock from encrypted cache
// ---------------------------------------------------------------------------

func TestIntegrationOfflineUnlockFromEncryptedCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cache.json")

	// Build a real cache snapshot with an item that has secrets.
	item := vault.Item{
		ID:   "item-1",
		Name: "SecretApp",
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			Username: "user@secret.com",
			Password: "supersecret123",
		},
	}
	itemsJSON, err := json.Marshal([]vault.Item{item})
	require.NoError(t, err)

	foldersJSON, err := json.Marshal([]vault.Folder{})
	require.NoError(t, err)

	plain := cache.PlainSnapshot{
		AccountHash:  "test-account-hash",
		LastRevision: "rev-1",
		SavedAt:      time.Now(),
		ItemsJSON:    itemsJSON,
		FoldersJSON:  foldersJSON,
	}
	plainJSON, err := json.Marshal(plain)
	require.NoError(t, err)

	password := "mypassword"
	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	require.NoError(t, err)
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	box := crypto.NewBox()
	ciphertext, err := box.Seal(plainJSON, key)
	require.NoError(t, err)

	snap := cache.Snapshot{
		Version:         cache.Version,
		AccountHash:     "test-account-hash",
		LastRevision:    "rev-1",
		SavedAt:         time.Now(),
		CacheKeySalt:    salt,
		VaultCiphertext: ciphertext,
	}

	// Save via real file store.
	store := file.NewStore(cachePath)
	err = store.Save(context.Background(), snap)
	require.NoError(t, err)

	// Verify raw file bytes do NOT contain plaintext secrets.
	raw, err := os.ReadFile(cachePath)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "SecretApp", "raw cache file must not contain item name")
	require.NotContains(t, string(raw), "user@secret.com", "raw cache file must not contain username")
	require.NotContains(t, string(raw), "supersecret123", "raw cache file must not contain password")
	require.NotContains(t, string(raw), "mypassword", "raw cache file must not contain password string")

	// No remote, no outbox.
	svc := NewService(Deps{
		Cache:     store,
		SecretBox: box,
	})

	// Unlock using the same password.
	err = svc.Unlock(context.Background(), "user@test.com", password)
	require.NoError(t, err)

	// Search must find the cached item.
	results, err := svc.Search(context.Background(), "SecretApp", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "SecretApp", results[0].Item.Name)
	require.Equal(t, "user@secret.com", results[0].Item.Login.Username)

	// Items endpoint also returns it.
	items, err := svc.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "SecretApp", items[0].Name)
}

// ---------------------------------------------------------------------------
// Test 2: Offline edit queues encrypted outbox
// ---------------------------------------------------------------------------

func TestIntegrationOfflineEditQueuesEncryptedOutbox(t *testing.T) {
	dir := t.TempDir()
	outboxPath := filepath.Join(dir, "outbox.json")
	box := crypto.NewBox()
	outboxStore := file.NewOutboxStore(outboxPath, box)

	// fakeRemote that fails updates (offline simulation).
	fr := &fakeRemote{
		updateErr: context.DeadlineExceeded,
	}

	svc := NewService(Deps{
		Remote: fr,
		Outbox: outboxStore,
	})

	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	svc.installUnlockedStateForTest(key, []vault.Item{
		{ID: "item-1", Name: "Original", Type: vault.ItemTypeLogin},
	})

	// Update offline — this should queue a mutation and persist to outbox.
	updated, err := svc.Update(context.Background(), "item-1", vault.Item{
		ID:   "item-1",
		Name: "OfflineUpdate",
		Type: vault.ItemTypeLogin,
	})
	require.NoError(t, err)
	require.Equal(t, vault.SyncStatusPending, updated.SyncStatus)

	// Wait for outbox file to appear (async save).
	var loaded []coresync.OutboxMutation
	require.Eventually(t, func() bool {
		// Load from outbox store with same key.
		svc.mu.Lock()
		key := make([]byte, len(svc.cacheKey))
		copy(key, svc.cacheKey)
		svc.mu.Unlock()

		var loadErr error
		loaded, loadErr = outboxStore.Load(context.Background(), key)
		return loadErr == nil && len(loaded) == 1
	}, 2*time.Second, 50*time.Millisecond, "outbox file should contain 1 mutation")

	require.Len(t, loaded, 1)
	require.Equal(t, coresync.MutationUpdate, loaded[0].Kind)
	require.Equal(t, "item-1", loaded[0].ItemID)

	// Verify raw outbox file bytes do NOT contain plaintext secrets.
	raw, err := os.ReadFile(outboxPath)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "OfflineUpdate", "raw outbox file must not contain item name")
	require.NotContains(t, string(raw), "item-1", "raw outbox file must not contain item ID in plaintext")

	// Decrypt loaded payload to confirm it has the correct name.
	var payloadItem vault.Item
	err = json.Unmarshal(loaded[0].Payload, &payloadItem)
	require.NoError(t, err)
	require.Equal(t, "OfflineUpdate", payloadItem.Name)
}

// ---------------------------------------------------------------------------
// Test 3: Remote revision unchanged skips full sync
// ---------------------------------------------------------------------------

func TestIntegrationRemoteRevisionEmptySkipsFullSync(t *testing.T) {
	fr := &fakeRemote{
		revisionRev: "",
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.mu.Unlock()

	// No outbox, no items.
	svc.syncOnce(context.Background())

	// Sync should NOT have been called because revision is empty and outbox empty.
	require.Equal(t, int32(0), fr.syncCalled.Load(), "Sync must not be called when revision is empty and no outbox")
}

// ---------------------------------------------------------------------------
// Test 4: Remote changed triggers full sync
// ---------------------------------------------------------------------------

func TestIntegrationRemoteChangedTriggersFullSync(t *testing.T) {
	remoteItem := vault.Item{
		ID:           "remote-1",
		Name:         "RemoteItem",
		Type:         vault.ItemTypeLogin,
		RevisionDate: time.Now(),
	}

	fr := &fakeRemote{
		revisionRev: "rev-2",
		syncItems:   []vault.Item{remoteItem},
		syncFolders: nil,
		syncRev:     "rev-3",
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.mu.Unlock()

	svc.syncOnce(context.Background())

	// Sync should have been called.
	require.Greater(t, fr.syncCalled.Load(), int32(0), "Sync must be called when revision is non-empty")

	// Items should contain the remote item.
	items, err := svc.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "RemoteItem", items[0].Name)
	require.Equal(t, vault.SyncStatusSynced, items[0].SyncStatus)
}

// ---------------------------------------------------------------------------
// Test 5: Conflict keep remote and duplicate local
// ---------------------------------------------------------------------------

func TestIntegrationConflictKeepRemoteAndDuplicateLocal(t *testing.T) {
	t.Run("keep remote", func(t *testing.T) {
		localItem := vault.Item{
			ID:   "item-1",
			Name: "LocalItem",
			Type: vault.ItemTypeLogin,
		}

		remoteItem := vault.Item{
			ID:           "item-1",
			Name:         "RemoteItem",
			Type:         vault.ItemTypeLogin,
			RevisionDate: time.Now().Add(time.Hour), // newer
		}

		fr := &fakeRemote{
			revisionRev: "rev-2",
			syncItems:   []vault.Item{remoteItem},
			syncFolders: nil,
			syncRev:     "rev-3",
		}

		svc := NewService(Deps{Remote: fr})
		svc.mu.Lock()
		svc.state = auth.LockStateUnlocked
		svc.items = []vault.Item{localItem}
		svc.outbox = []coresync.OutboxMutation{
			{ID: "m1", Kind: coresync.MutationUpdate, ItemID: "item-1", Payload: []byte(`{"name":"UpdatedLocally"}`)},
		}
		svc.rebuildIndexLocked()
		svc.mu.Unlock()

		// Trigger sync — should detect conflict.
		svc.syncOnce(context.Background())

		conflicts := svc.conflictsForTest()
		require.Len(t, conflicts, 1, "expected 1 conflict")
		require.Equal(t, "item-1", conflicts[0].ItemID)

		// Resolve: keep remote.
		err := svc.ResolveConflict(context.Background(), conflicts[0].ID, coresync.ResolutionKeepRemote)
		require.NoError(t, err)

		items, err := svc.Items(context.Background())
		require.NoError(t, err)
		require.Len(t, items, 1)
		require.Equal(t, "RemoteItem", items[0].Name, "local item should be replaced by remote")
		require.Equal(t, vault.SyncStatusSynced, items[0].SyncStatus)

		// Outbox mutation for original item should be removed.
		pending := svc.pendingMutationsForTest()
		require.Len(t, pending, 0, "outbox should be cleared for resolved conflict item")
	})

	t.Run("duplicate local", func(t *testing.T) {
		localItem := vault.Item{
			ID:   "item-2",
			Name: "LocalItem2",
			Type: vault.ItemTypeLogin,
		}

		remoteItem := vault.Item{
			ID:           "item-2",
			Name:         "RemoteItem2",
			Type:         vault.ItemTypeLogin,
			RevisionDate: time.Now().Add(time.Hour), // newer
		}

		fr := &fakeRemote{
			revisionRev: "rev-2",
			syncItems:   []vault.Item{remoteItem},
			syncFolders: nil,
			syncRev:     "rev-3",
		}

		svc := NewService(Deps{Remote: fr})
		svc.mu.Lock()
		svc.state = auth.LockStateUnlocked
		svc.items = []vault.Item{localItem}
		svc.outbox = []coresync.OutboxMutation{
			{ID: "m2", Kind: coresync.MutationUpdate, ItemID: "item-2", Payload: []byte(`{"name":"LocallyUpdated2"}`)},
		}
		svc.rebuildIndexLocked()
		svc.mu.Unlock()

		// Trigger sync.
		svc.syncOnce(context.Background())

		conflicts := svc.conflictsForTest()
		require.Len(t, conflicts, 1, "expected 1 conflict")
		require.Equal(t, "item-2", conflicts[0].ItemID)

		// Resolve: duplicate local.
		err := svc.ResolveConflict(context.Background(), conflicts[0].ID, coresync.ResolutionDuplicateLocal)
		require.NoError(t, err)

		items, err := svc.Items(context.Background())
		require.NoError(t, err)
		require.Len(t, items, 2, "expected original + duplicate")

		var original, duplicate vault.Item
		for _, it := range items {
			if it.ID == "item-2" {
				original = it
			} else {
				duplicate = it
			}
		}

		// Original should be the remote version (synced).
		require.Equal(t, "RemoteItem2", original.Name)
		require.Equal(t, vault.SyncStatusSynced, original.SyncStatus)

		// Duplicate should be a new local pending item.
		require.Contains(t, duplicate.ID, "local-")
		require.Equal(t, vault.SyncStatusPending, duplicate.SyncStatus)
		require.Equal(t, "LocalItem2", duplicate.Name)

		// Outbox should contain one create mutation for the duplicate.
		pending := svc.pendingMutationsForTest()
		require.Len(t, pending, 1, "expected 1 outbox mutation (create for duplicate)")
		require.Equal(t, coresync.MutationCreate, pending[0].Kind)
		require.Equal(t, duplicate.ID, pending[0].ItemID)
	})
}

// ---------------------------------------------------------------------------
// Test 6: Relock cancels stale worker
// ---------------------------------------------------------------------------

func TestIntegrationRelockCancelsStaleWorker(t *testing.T) {
	fr := &fakeRemote{
		revisionRev: "rev-2",
		syncBlockCh: make(chan struct{}),
		syncEnterCh: make(chan struct{}, 1),
		syncItems:   []vault.Item{{ID: "remote-1", Name: "StaleItem", Type: vault.ItemTypeLogin}},
		syncFolders: nil,
		syncRev:     "rev-3",
	}

	// Use a cache that returns os.ErrNotExist so Unlock skips cache load
	// without panicking on a nil Cache dereference.
	fakCache := &fakeCache{
		loadErr: os.ErrNotExist,
	}

	svc := NewService(Deps{
		Remote:    fr,
		Cache:     fakCache,
		SecretBox: &fakeSecretBox{},
	})

	// Unlock (this starts sync worker).
	err := svc.Unlock(context.Background(), "user@test.com", "password")
	require.NoError(t, err)

	// Wait for sync worker to reach Sync (blocked on syncBlockCh).
	<-fr.syncEnterCh

	// Lock while sync worker is blocked.
	err = svc.Lock(context.Background())
	require.NoError(t, err)

	// Unblock the sync worker AFTER Lock.
	close(fr.syncBlockCh)

	// Wait for context cancellation to propagate.
	require.Eventually(t, func() bool {
		svc.mu.Lock()
		defer svc.mu.Unlock()
		return svc.state == auth.LockStateLocked && svc.items == nil
	}, 1*time.Second, 10*time.Millisecond, "service should be locked with no items")

	// Verify service is locked.
	_, err = svc.Search(context.Background(), "StaleItem", 10)
	require.ErrorIs(t, err, coreerrors.ErrLocked)

	// Verify no items are installed.
	svc.mu.Lock()
	require.Nil(t, svc.items, "items must be nil after lock")
	require.Nil(t, svc.index, "index must be nil after lock")
	svc.mu.Unlock()
}
