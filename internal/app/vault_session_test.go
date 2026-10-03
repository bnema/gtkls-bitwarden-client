package app

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	cerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// sessionFixture is one vault state installed into a Service in either session
// mode, backed by the same fakes, so the public methods can be compared across
// modes.
type sessionFixture struct {
	items     []vault.Item
	outbox    []coresync.OutboxMutation
	conflicts []coresync.Conflict
	remote    *fakeRemote
}

func newSessionFixture() sessionFixture {
	return sessionFixture{
		items: []vault.Item{
			{ID: "item-1", Name: "GitHub", Type: vault.ItemTypeLogin, SyncStatus: vault.SyncStatusConflict, ConflictID: "c1", Login: &vault.Login{Username: "local-user"}},
			{ID: "item-2", Name: "Mail", Type: vault.ItemTypeLogin},
		},
		outbox: []coresync.OutboxMutation{{
			ID: "m1", Kind: coresync.MutationUpdate, ItemID: "item-1", BaseRevision: "old-rev",
			Payload: []byte(`{"id":"item-1","name":"GitHub","type":"login"}`),
		}},
		conflicts: []coresync.Conflict{{ID: "c1", ItemID: "item-1", MutationID: "m1", Reason: coresync.ConflictBothModified, RemoteRevision: "new-rev"}},
		remote: &fakeRemote{
			revisionRev: "rev-2",
			syncRev:     "rev-2",
			syncItems: []vault.Item{
				{ID: "item-1", Name: "GitHub Remote", Type: vault.ItemTypeLogin, RevisionDate: time.Now()},
				{ID: "item-2", Name: "Mail", Type: vault.ItemTypeLogin, RevisionDate: time.Now()},
			},
		},
	}
}

// service returns an unlocked Service in the given mode. In resident mode the
// fixture is held in memory; in cache-only mode it is only in the encrypted
// cache and resident plaintext is empty.
func (f sessionFixture) service(t *testing.T, mode sessionMode) *Service {
	t.Helper()
	key := []byte("test-cache-key-32-bytes-long!")
	snap := buildCacheSnapshotWithKeyAndOutboxAndConflicts(t, key, f.items, nil, f.outbox, f.conflicts)
	svc := NewService(Deps{
		Remote:    f.remote,
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})
	svc.mu.Lock()
	defer svc.mu.Unlock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], key...)
	svc.sessionMode = mode
	svc.conflicts = append([]coresync.Conflict(nil), f.conflicts...)
	if mode == sessionResident {
		svc.items = cloneVaultItems(f.items)
		svc.outbox = append([]coresync.OutboxMutation(nil), f.outbox...)
		svc.cacheSalt = []byte("0123456789abcdef")
	}
	return svc
}

var sessionModes = []struct {
	name string
	mode sessionMode
}{
	{"resident", sessionResident},
	{"cache-only", sessionCacheOnly},
}

func TestSessionReadsAgreeAcrossModes(t *testing.T) {
	for _, tc := range sessionModes {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSessionFixture().service(t, tc.mode)
			ctx := context.Background()

			items, err := svc.Items(ctx)
			require.NoError(t, err)
			require.Len(t, items, 2)

			found, err := svc.Search(ctx, "github", 10)
			require.NoError(t, err)
			require.Len(t, found, 1)
			require.Equal(t, "GitHub", found[0].Item.Name)

			got, err := svc.Get(ctx, "item-2")
			require.NoError(t, err)
			require.Equal(t, "Mail", got.Name)

			_, err = svc.Get(ctx, "missing")
			require.ErrorIs(t, err, cerrors.ErrNotFound)

			conflicts, err := svc.Conflicts(ctx)
			require.NoError(t, err)
			require.Len(t, conflicts, 1)

			// Reads never make a cache-only session resident.
			svc.mu.Lock()
			defer svc.mu.Unlock()
			if tc.mode == sessionCacheOnly {
				require.Nil(t, svc.items)
				require.Nil(t, svc.outbox)
			}
		})
	}
}

func TestSessionReadsRequireUnlockInBothModes(t *testing.T) {
	for _, tc := range sessionModes {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSessionFixture().service(t, tc.mode)
			require.NoError(t, svc.SoftLock(context.Background()))

			_, err := svc.Items(context.Background())
			require.ErrorIs(t, err, cerrors.ErrLocked)
			_, err = svc.Search(context.Background(), "git", 5)
			require.ErrorIs(t, err, cerrors.ErrLocked)
			_, err = svc.Get(context.Background(), "item-1")
			require.ErrorIs(t, err, cerrors.ErrLocked)
			_, err = svc.ConflictDetail(context.Background(), "c1")
			require.ErrorIs(t, err, cerrors.ErrLocked)
		})
	}
}

func TestSessionModeIsExplicitNotInferredFromResidentState(t *testing.T) {
	f := newSessionFixture()

	// A resident session with empty resident state and a cache key does not
	// borrow from the encrypted cache: the mode, not emptiness, decides.
	resident := f.service(t, sessionResident)
	resident.mu.Lock()
	resident.items = nil
	resident.outbox = nil
	resident.mu.Unlock()
	items, err := resident.Items(context.Background())
	require.NoError(t, err)
	require.Empty(t, items)

	// A cache-only session ignores any resident plaintext it might hold.
	cacheOnly := f.service(t, sessionCacheOnly)
	cacheOnly.mu.Lock()
	cacheOnly.items = []vault.Item{{ID: "stray", Name: "Stray", Type: vault.ItemTypeLogin}}
	cacheOnly.mu.Unlock()
	items, err = cacheOnly.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 2)
	for _, item := range items {
		require.NotEqual(t, "stray", item.ID)
	}
}

func TestSessionConflictDetailAcrossModes(t *testing.T) {
	for _, tc := range sessionModes {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSessionFixture().service(t, tc.mode)

			detail, err := svc.ConflictDetail(context.Background(), "c1")
			require.NoError(t, err)
			require.Equal(t, "c1", detail.Conflict.ID)
			require.NotNil(t, detail.LocalItem)
			require.Equal(t, "GitHub", detail.LocalItem.Name)
			require.NotNil(t, detail.RemoteItem)
			require.Equal(t, "GitHub Remote", detail.RemoteItem.Name)

			_, err = svc.ConflictDetail(context.Background(), "unknown")
			require.ErrorIs(t, err, cerrors.ErrNotFound)
		})
	}
}

func TestSessionResolveConflictKeepRemoteAcrossModes(t *testing.T) {
	for _, tc := range sessionModes {
		t.Run(tc.name, func(t *testing.T) {
			svc := newSessionFixture().service(t, tc.mode)
			if tc.mode == sessionResident {
				svc.mu.Lock()
				svc.pendingRemoteItems = cloneVaultItems(svc.deps.Remote.(*fakeRemote).syncItems)
				svc.mu.Unlock()
			}

			require.NoError(t, svc.ResolveConflict(context.Background(), "c1", coresync.ResolutionKeepRemote))

			got, err := svc.Get(context.Background(), "item-1")
			require.NoError(t, err)
			require.Equal(t, "GitHub Remote", got.Name)
			require.Equal(t, vault.SyncStatusSynced, got.SyncStatus)

			conflicts, err := svc.Conflicts(context.Background())
			require.NoError(t, err)
			require.Empty(t, conflicts)

			err = svc.ResolveConflict(context.Background(), "c1", coresync.ResolutionKeepRemote)
			require.ErrorIs(t, err, cerrors.ErrNotFound)
		})
	}
}

func TestSessionSyncNowAcrossModes(t *testing.T) {
	for _, tc := range sessionModes {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionFixture()
			f.outbox = nil
			f.conflicts = nil
			svc := f.service(t, tc.mode)

			require.NoError(t, svc.SyncNow(context.Background()))

			items, err := svc.Items(context.Background())
			require.NoError(t, err)
			require.Len(t, items, 2)
			byID := map[string]vault.Item{}
			for _, item := range items {
				byID[item.ID] = item
			}
			require.Equal(t, "GitHub Remote", byID["item-1"].Name)
			require.Equal(t, vault.SyncStatusSynced, byID["item-1"].SyncStatus)

			// Only resident sessions install plaintext into the service.
			svc.mu.Lock()
			defer svc.mu.Unlock()
			if tc.mode == sessionResident {
				require.Len(t, svc.items, 2)
			} else {
				require.Nil(t, svc.items)
			}
		})
	}
}

func TestSessionSyncNowRequiresUnlock(t *testing.T) {
	svc := NewService(Deps{Remote: &fakeRemote{}})
	require.ErrorIs(t, svc.SyncNow(context.Background()), cerrors.ErrLocked)
}

func TestSessionModeResetOnLockAndShutdown(t *testing.T) {
	svc := newSessionFixture().service(t, sessionCacheOnly)
	svc.mu.Lock()
	svc.backgroundSyncActive = true
	svc.mu.Unlock()

	require.NoError(t, svc.SoftLock(context.Background()))
	svc.mu.Lock()
	require.Equal(t, sessionResident, svc.sessionMode)
	require.False(t, svc.backgroundSyncActive)
	svc.mu.Unlock()

	svc = newSessionFixture().service(t, sessionCacheOnly)
	require.NoError(t, svc.Shutdown(context.Background()))
	svc.mu.Lock()
	require.Equal(t, sessionResident, svc.sessionMode)
	svc.mu.Unlock()
}
