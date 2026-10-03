package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	cerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
)

// mutationCase drives one mutation kind through the public Service API and
// states what the vault must look like afterwards. The same table runs for
// every outcome (remote ok / remote error) and session mode.
type mutationCase struct {
	name string
	kind coresync.MutationKind

	// run calls the public method under test.
	run func(svc *Service) error
	// failRemote / succeedRemote configure the fake remote's response.
	failRemote    func(r *fakeRemote)
	succeedRemote func(r *fakeRemote)

	// want maps item ID (or "" for the single locally generated ID) to the
	// expected state after the mutation, per outcome. A nil entry means the
	// item must be gone.
	synced  map[string]*vault.Item
	pending map[string]*vault.Item

	pendingItemID string // expected outbox ItemID ("local-" prefix match if ending in "*")
	syncedMsg     string
	pendingMsg    string
}

func mutationBase() []vault.Item {
	return []vault.Item{
		{ID: "item-1", Name: "One", Type: vault.ItemTypeLogin},
		{ID: "item-2", Name: "Two", Type: vault.ItemTypeLogin, Deleted: true},
		{ID: "item-3", Name: "Three", Type: vault.ItemTypeLogin},
	}
}

var errRemoteDown = errors.New("remote down")

func mutationCases() []mutationCase {
	return []mutationCase{
		{
			name: "create", kind: coresync.MutationCreate,
			run: func(svc *Service) error {
				_, err := svc.Create(context.Background(), vault.Item{Name: "New", Type: vault.ItemTypeLogin})
				return err
			},
			failRemote: func(r *fakeRemote) { r.createErr = errRemoteDown },
			succeedRemote: func(r *fakeRemote) {
				r.createItem = vault.Item{ID: "remote-new", Name: "New (remote)", Type: vault.ItemTypeLogin}
			},
			synced:        map[string]*vault.Item{"remote-new": {Name: "New (remote)", SyncStatus: vault.SyncStatusSynced}},
			pending:       map[string]*vault.Item{"": {Name: "New", SyncStatus: vault.SyncStatusPending}},
			pendingItemID: "local-*",
			syncedMsg:     "item created remotely", pendingMsg: "item queued for creation",
		},
		{
			name: "update", kind: coresync.MutationUpdate,
			run: func(svc *Service) error {
				_, err := svc.Update(context.Background(), "item-1", vault.Item{Name: "One v2", Type: vault.ItemTypeLogin})
				return err
			},
			failRemote: func(r *fakeRemote) { r.updateErr = errRemoteDown },
			succeedRemote: func(r *fakeRemote) {
				r.updateItem = vault.Item{ID: "item-1", Name: "One v2 (remote)", Type: vault.ItemTypeLogin}
			},
			synced:        map[string]*vault.Item{"item-1": {Name: "One v2 (remote)", SyncStatus: vault.SyncStatusSynced}},
			pending:       map[string]*vault.Item{"item-1": {Name: "One v2", SyncStatus: vault.SyncStatusPending}},
			pendingItemID: "item-1",
			syncedMsg:     "item updated remotely", pendingMsg: "item queued for update",
		},
		{
			name: "trash", kind: coresync.MutationTrash,
			run:        func(svc *Service) error { return svc.Trash(context.Background(), "item-1") },
			failRemote: func(r *fakeRemote) { r.trashErr = errRemoteDown },
			synced:     map[string]*vault.Item{"item-1": {Name: "One", Deleted: true, SyncStatus: vault.SyncStatusSynced}},
			pending:    map[string]*vault.Item{"item-1": {Name: "One", Deleted: true, SyncStatus: vault.SyncStatusPending}},

			pendingItemID: "item-1",
			syncedMsg:     "item trashed remotely", pendingMsg: "item queued for trash",
		},
		{
			name: "restore", kind: coresync.MutationRestore,
			run: func(svc *Service) error {
				_, err := svc.Restore(context.Background(), "item-2")
				return err
			},
			failRemote: func(r *fakeRemote) { r.restoreErr = errRemoteDown },
			succeedRemote: func(r *fakeRemote) {
				r.restoreItem = vault.Item{ID: "item-2", Name: "Two (remote)", Type: vault.ItemTypeLogin}
			},
			synced:        map[string]*vault.Item{"item-2": {Name: "Two (remote)", SyncStatus: vault.SyncStatusSynced}},
			pending:       map[string]*vault.Item{"item-2": {Name: "Two", SyncStatus: vault.SyncStatusPending}},
			pendingItemID: "item-2",
			syncedMsg:     "item restored remotely", pendingMsg: "item queued for restore",
		},
		{
			name: "delete", kind: coresync.MutationDelete,
			run:        func(svc *Service) error { return svc.Delete(context.Background(), "item-3") },
			failRemote: func(r *fakeRemote) { r.deleteErr = errRemoteDown },
			synced:     map[string]*vault.Item{"item-3": nil},
			pending:    map[string]*vault.Item{"item-3": nil},

			pendingItemID: "item-3",
			syncedMsg:     "item deleted remotely", pendingMsg: "item queued for deletion",
		},
	}
}

func lastEvent(svc *Service) (Event, bool) {
	var last Event
	var ok bool
	for {
		select {
		case e := <-svc.events:
			last, ok = e, true
		default:
			return last, ok
		}
	}
}

// vaultState returns the items and outbox the session would serve to a reader
// after pending cache saves have settled.
func vaultState(t *testing.T, svc *Service) (map[string]vault.Item, []coresync.OutboxMutation) {
	t.Helper()
	svc.saveWG.Wait()
	svc.mu.Lock()
	view := svc.sessionViewLocked(true)
	svc.mu.Unlock()
	defer view.close()
	snap, err := view.load(context.Background(), svc.vaultCache())
	require.NoError(t, err)
	byID := make(map[string]vault.Item, len(snap.Items))
	for _, it := range snap.Items {
		byID[it.ID] = it
	}
	return byID, snap.Outbox
}

func requireItemState(t *testing.T, got map[string]vault.Item, want map[string]*vault.Item, base []vault.Item) {
	t.Helper()
	touched := map[string]bool{}
	for id, w := range want {
		if id == "" { // locally generated ID
			var found *vault.Item
			for _, it := range got {
				if strings.HasPrefix(it.ID, "local-") {
					it := it
					found = &it
				}
			}
			require.NotNil(t, found, "locally created item missing")
			require.Equal(t, w.Name, found.Name)
			require.Equal(t, w.SyncStatus, found.SyncStatus)
			continue
		}
		touched[id] = true
		it, ok := got[id]
		if w == nil {
			require.False(t, ok, "item %s should be gone", id)
			continue
		}
		require.True(t, ok, "item %s missing", id)
		require.Equal(t, w.Name, it.Name, id)
		require.Equal(t, w.Deleted, it.Deleted, id)
		require.Equal(t, w.SyncStatus, it.SyncStatus, id)
	}
	for _, b := range base {
		if !touched[b.ID] {
			require.Equal(t, b.Name, got[b.ID].Name, "untouched item %s changed", b.ID)
			require.Equal(t, b.Deleted, got[b.ID].Deleted, "untouched item %s changed", b.ID)
		}
	}
}

func newMutationService(t *testing.T, mode sessionMode, remote *fakeRemote) *Service {
	t.Helper()
	f := sessionFixture{items: mutationBase(), remote: remote}
	return f.service(t, mode)
}

func TestMutationRemoteSucceeds(t *testing.T) {
	for _, tc := range sessionModes {
		for _, mc := range mutationCases() {
			t.Run(tc.name+"/"+mc.name, func(t *testing.T) {
				remote := &fakeRemote{}
				if mc.succeedRemote != nil {
					mc.succeedRemote(remote)
				}
				svc := newMutationService(t, tc.mode, remote)

				require.NoError(t, mc.run(svc))

				items, outbox := vaultState(t, svc)
				requireItemState(t, items, mc.synced, mutationBase())
				require.Empty(t, outbox, "a confirmed mutation must not be queued")

				evt, ok := lastEvent(svc)
				require.True(t, ok)
				require.Equal(t, in.SyncUpdated, evt.Kind)
				require.Equal(t, mc.syncedMsg, evt.Message)
			})
		}
	}
}

func TestMutationRemoteErrorQueuesInOutbox(t *testing.T) {
	for _, tc := range sessionModes {
		for _, mc := range mutationCases() {
			t.Run(tc.name+"/"+mc.name, func(t *testing.T) {
				remote := &fakeRemote{}
				mc.failRemote(remote)
				svc := newMutationService(t, tc.mode, remote)

				require.NoError(t, mc.run(svc))

				items, outbox := vaultState(t, svc)
				requireItemState(t, items, mc.pending, mutationBase())
				require.Len(t, outbox, 1)
				require.Equal(t, mc.kind, outbox[0].Kind)
				require.True(t, strings.HasPrefix(outbox[0].ID, "m-"), outbox[0].ID)
				if strings.HasSuffix(mc.pendingItemID, "*") {
					require.True(t, strings.HasPrefix(outbox[0].ItemID, strings.TrimSuffix(mc.pendingItemID, "*")), outbox[0].ItemID)
				} else {
					require.Equal(t, mc.pendingItemID, outbox[0].ItemID)
				}

				evt, ok := lastEvent(svc)
				require.True(t, ok)
				require.Equal(t, in.MutationPending, evt.Kind)
				require.Equal(t, mc.pendingMsg, evt.Message)
			})
		}
	}
}

func TestMutationWithoutRemoteQueuesInOutbox(t *testing.T) {
	for _, mc := range mutationCases() {
		t.Run(mc.name, func(t *testing.T) {
			svc := newMutationService(t, sessionResident, nil)
			svc.deps.Remote = nil

			require.NoError(t, mc.run(svc))

			items, outbox := vaultState(t, svc)
			requireItemState(t, items, mc.pending, mutationBase())
			require.Len(t, outbox, 1)
			require.Equal(t, mc.kind, outbox[0].Kind)
		})
	}
}

func TestMutationRequiresUnlockInBothModes(t *testing.T) {
	for _, tc := range sessionModes {
		for _, mc := range mutationCases() {
			t.Run(tc.name+"/"+mc.name, func(t *testing.T) {
				remote := &fakeRemote{}
				svc := newMutationService(t, tc.mode, remote)
				require.NoError(t, svc.SoftLock(context.Background()))

				require.ErrorIs(t, mc.run(svc), cerrors.ErrLocked)
			})
		}
	}
}

func TestMutationReturnValues(t *testing.T) {
	ctx := context.Background()
	remote := &fakeRemote{
		updateItem:  vault.Item{ID: "item-1", Name: "One (remote)"},
		restoreItem: vault.Item{ID: "item-2", Name: "Two (remote)", Deleted: true},
	}
	svc := newMutationService(t, sessionResident, remote)

	got, err := svc.Update(ctx, "item-1", vault.Item{Name: "x"})
	require.NoError(t, err)
	require.Equal(t, "One (remote)", got.Name)
	require.Equal(t, vault.SyncStatusSynced, got.SyncStatus)

	// Restore always clears Deleted, whatever the remote returned.
	got, err = svc.Restore(ctx, "item-2")
	require.NoError(t, err)
	require.False(t, got.Deleted)
	require.Equal(t, vault.SyncStatusSynced, got.SyncStatus)

	remote.createErr = errRemoteDown
	got, err = svc.Create(ctx, vault.Item{Name: "Offline"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(got.ID, "local-"), got.ID)
	require.Equal(t, vault.SyncStatusPending, got.SyncStatus)
	require.False(t, got.RevisionDate.IsZero())

	// A caller-supplied ID is kept.
	got, err = svc.Create(ctx, vault.Item{ID: "given", Name: "Given"})
	require.NoError(t, err)
	require.Equal(t, "given", got.ID)

	remote.updateErr = errRemoteDown
	got, err = svc.Update(ctx, "item-3", vault.Item{ID: "ignored", Name: "Three v2"})
	require.NoError(t, err)
	require.Equal(t, "item-3", got.ID, "Update forces the target ID")
	require.Equal(t, vault.SyncStatusPending, got.SyncStatus)
}

// recordingRemote records the calls the outbox replay makes.
type recordingRemote struct {
	*fakeRemote
	calls []string
	items map[string]vault.Item
	err   error
}

func (r *recordingRemote) Create(_ context.Context, item vault.Item) (vault.Item, error) {
	r.calls = append(r.calls, "create:"+item.ID)
	r.items["create"] = item
	return item, r.err
}

func (r *recordingRemote) Update(_ context.Context, id string, item vault.Item) (vault.Item, error) {
	r.calls = append(r.calls, "update:"+id)
	r.items["update"] = item
	return item, r.err
}

func (r *recordingRemote) Trash(_ context.Context, id string) error {
	r.calls = append(r.calls, "trash:"+id)
	return r.err
}

func (r *recordingRemote) Restore(_ context.Context, id string) (vault.Item, error) {
	r.calls = append(r.calls, "restore:"+id)
	return vault.Item{ID: id}, r.err
}

func (r *recordingRemote) Delete(_ context.Context, id string) error {
	r.calls = append(r.calls, "delete:"+id)
	return r.err
}

// TestReplayOutboxRoundTripsEveryKind queues each kind offline, then replays
// the resulting outbox entry: the payload encoded by the shared definition
// must decode into the same remote call.
func TestReplayOutboxRoundTripsEveryKind(t *testing.T) {
	for _, mc := range mutationCases() {
		t.Run(mc.name, func(t *testing.T) {
			failing := &fakeRemote{}
			mc.failRemote(failing)
			svc := newMutationService(t, sessionResident, failing)
			require.NoError(t, mc.run(svc))
			_, queued := vaultState(t, svc)
			require.Len(t, queued, 1)

			rec := &recordingRemote{fakeRemote: &fakeRemote{}, items: map[string]vault.Item{}}
			svc.deps.Remote = rec
			require.NoError(t, svc.replayOutbox(context.Background(), queued))

			require.Equal(t, []string{string(mc.kind) + ":" + queued[0].ItemID}, rec.calls)
			switch mc.kind {
			case coresync.MutationCreate:
				require.Equal(t, "New", rec.items["create"].Name)
				require.True(t, strings.HasPrefix(rec.items["create"].ID, "local-"))
			case coresync.MutationUpdate:
				require.Equal(t, "One v2", rec.items["update"].Name)
				require.Equal(t, "item-1", rec.items["update"].ID)
			}
		})
	}
}

func TestReplayOutboxErrors(t *testing.T) {
	ctx := context.Background()
	svc := NewService(Deps{Remote: &recordingRemote{fakeRemote: &fakeRemote{}, items: map[string]vault.Item{}}})

	err := svc.replayOutbox(ctx, []coresync.OutboxMutation{{ID: "m1", Kind: coresync.MutationFolderChange}})
	require.ErrorIs(t, err, cerrors.ErrUnsupported)
	require.Contains(t, err.Error(), "unknown mutation kind folder_change")

	err = svc.replayOutbox(ctx, []coresync.OutboxMutation{{ID: "m1", Kind: coresync.MutationUpdate, ItemID: "i", Payload: []byte("{")}})
	require.ErrorContains(t, err, "replay unmarshal:")

	boom := errors.New("boom")
	svc = NewService(Deps{Remote: &recordingRemote{fakeRemote: &fakeRemote{}, items: map[string]vault.Item{}, err: boom}})
	for _, kind := range []coresync.MutationKind{coresync.MutationCreate, coresync.MutationUpdate, coresync.MutationTrash, coresync.MutationRestore, coresync.MutationDelete} {
		err = svc.replayOutbox(ctx, []coresync.OutboxMutation{{ID: "m1", Kind: kind, ItemID: "i", Payload: []byte(`{"id":"i"}`)}})
		require.ErrorIs(t, err, boom)
		require.Contains(t, err.Error(), "replay "+string(kind)+": ")
	}

	// Cancelled context stops replay before any call.
	rec := &recordingRemote{fakeRemote: &fakeRemote{}, items: map[string]vault.Item{}}
	svc = NewService(Deps{Remote: rec})
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	err = svc.replayOutbox(cctx, []coresync.OutboxMutation{{ID: "m1", Kind: coresync.MutationDelete, ItemID: "i"}})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, rec.calls)
}

func TestOfflineMutationIDs(t *testing.T) {
	remote := &fakeRemote{createErr: errRemoteDown}
	svc := newMutationService(t, sessionResident, remote)
	before := time.Now()

	a, err := svc.Create(context.Background(), vault.Item{Name: "A"})
	require.NoError(t, err)
	b, err := svc.Create(context.Background(), vault.Item{Name: "B"})
	require.NoError(t, err)
	require.NotEqual(t, a.ID, b.ID)

	_, outbox := vaultState(t, svc)
	require.Len(t, outbox, 2)
	require.NotEqual(t, outbox[0].ID, outbox[1].ID)
	require.False(t, outbox[0].CreatedAt.Before(before))
}

// TestCacheOnlyMutationsPreserveEncryptedCache covers PIN sessions, whose
// resident items and outbox are empty: a mutation must patch the encrypted
// cache (items and outbox) and never overwrite it from the empty resident
// state, whether the remote confirmed it or it was queued offline.
func TestCacheOnlyMutationsPreserveEncryptedCache(t *testing.T) {
	existing := coresync.OutboxMutation{
		ID: "m-existing", Kind: coresync.MutationUpdate, ItemID: "item-3",
		Payload: []byte(`{"id":"item-3","name":"Three","type":"login"}`),
	}
	for _, mc := range mutationCases() {
		for _, offline := range []bool{false, true} {
			name := mc.name + "/remote-ok"
			if offline {
				name = mc.name + "/remote-error"
			}
			t.Run(name, func(t *testing.T) {
				remote := &fakeRemote{}
				want, wantOutbox := mc.synced, 1
				if offline {
					mc.failRemote(remote)
					want, wantOutbox = mc.pending, 2
				} else if mc.succeedRemote != nil {
					mc.succeedRemote(remote)
				}
				f := sessionFixture{items: mutationBase(), outbox: []coresync.OutboxMutation{existing}, remote: remote}
				svc := f.service(t, sessionCacheOnly)

				require.NoError(t, mc.run(svc))

				items, outbox := vaultState(t, svc)
				requireItemState(t, items, want, mutationBase())
				require.Len(t, outbox, wantOutbox)
				require.Equal(t, existing.ID, outbox[0].ID, "previously queued mutation must survive")
				if offline {
					require.Equal(t, mc.kind, outbox[1].Kind)
				}

				// Resident plaintext stays empty in a cache-only session.
				svc.mu.Lock()
				defer svc.mu.Unlock()
				require.Empty(t, svc.items)
				require.Empty(t, svc.outbox)
			})
		}
	}
}

func TestCacheOnlyOfflineMutationsAccumulateInOutbox(t *testing.T) {
	remote := &fakeRemote{trashErr: errRemoteDown, deleteErr: errRemoteDown}
	f := sessionFixture{items: mutationBase(), remote: remote}
	svc := f.service(t, sessionCacheOnly)

	require.NoError(t, svc.Trash(context.Background(), "item-1"))
	svc.saveWG.Wait()
	require.NoError(t, svc.Delete(context.Background(), "item-3"))

	items, outbox := vaultState(t, svc)
	require.Len(t, outbox, 2)
	require.Equal(t, coresync.MutationTrash, outbox[0].Kind)
	require.Equal(t, coresync.MutationDelete, outbox[1].Kind)
	require.True(t, items["item-1"].Deleted)
	require.NotContains(t, items, "item-3")
	require.Contains(t, items, "item-2")
}

// TestCacheOnlyBackToBackMutationsAreNotCoalesced holds the cache writer so
// that two cache-only mutations are queued before either save runs. The older
// save is then stale; its patch must still reach the encrypted cache.
func TestCacheOnlyBackToBackMutationsAreNotCoalesced(t *testing.T) {
	remote := &fakeRemote{trashErr: errRemoteDown, deleteErr: errRemoteDown}
	f := sessionFixture{items: mutationBase(), remote: remote}
	svc := f.service(t, sessionCacheOnly)

	svc.cacheSaveMu.Lock()
	require.NoError(t, svc.Trash(context.Background(), "item-1"))
	require.NoError(t, svc.Delete(context.Background(), "item-3"))
	svc.cacheSaveMu.Unlock()

	items, outbox := vaultState(t, svc)
	require.Len(t, outbox, 2)
	require.True(t, items["item-1"].Deleted)
	require.NotContains(t, items, "item-3")
}

// itemsOnlyRemote implements only out.RemoteItems: mutation specs must not
// need any other remote capability.
type itemsOnlyRemote struct{ calls []string }

func (r *itemsOnlyRemote) Create(_ context.Context, item vault.Item) (vault.Item, error) {
	r.calls = append(r.calls, "create")
	return item, nil
}

func (r *itemsOnlyRemote) Update(_ context.Context, id string, item vault.Item) (vault.Item, error) {
	r.calls = append(r.calls, "update:"+id)
	return item, nil
}

func (r *itemsOnlyRemote) Trash(_ context.Context, id string) error {
	r.calls = append(r.calls, "trash:"+id)
	return nil
}

func (r *itemsOnlyRemote) Restore(_ context.Context, id string) (vault.Item, error) {
	r.calls = append(r.calls, "restore:"+id)
	return vault.Item{ID: id}, nil
}

func (r *itemsOnlyRemote) Delete(_ context.Context, id string) error {
	r.calls = append(r.calls, "delete:"+id)
	return nil
}

func TestMutationSpecsDependOnlyOnRemoteItems(t *testing.T) {
	r := &itemsOnlyRemote{}
	m := mutation{ID: "item-1", Item: vault.Item{ID: "item-1"}}
	for _, kind := range []coresync.MutationKind{
		coresync.MutationCreate, coresync.MutationUpdate, coresync.MutationTrash,
		coresync.MutationRestore, coresync.MutationDelete,
	} {
		spec, ok := mutationSpecFor(kind)
		require.True(t, ok, kind)
		_, err := spec.call(context.Background(), r, m)
		require.NoError(t, err, kind)
	}
	require.Equal(t, []string{"create", "update:item-1", "trash:item-1", "restore:item-1", "delete:item-1"}, r.calls)
}

// TestCacheOnlyMutationSurvivesUnreadableCache makes the encrypted cache
// unreadable when an offline mutation is flushed. The queued outbox entry must
// still become durable, and the whole mutation must be applied once the cache
// can be read again, without duplicating the outbox entry.
func TestCacheOnlyMutationSurvivesUnreadableCache(t *testing.T) {
	existing := coresync.OutboxMutation{
		ID: "m-existing", Kind: coresync.MutationUpdate, ItemID: "item-3",
		Payload: []byte(`{"id":"item-3","name":"Three","type":"login"}`),
	}
	remote := &fakeRemote{createErr: errRemoteDown, trashErr: errRemoteDown}
	f := sessionFixture{items: mutationBase(), remote: remote}
	svc := f.service(t, sessionCacheOnly)
	fc := svc.deps.Cache.(*fakeCache)
	ob := &fakeOutbox{loadData: []coresync.OutboxMutation{existing}}
	svc.deps.Outbox = ob

	fc.mu.Lock()
	fc.loadErr = errors.New("cache unreadable")
	fc.mu.Unlock()
	created, err := svc.Create(context.Background(), vault.Item{Name: "Offline"})
	require.NoError(t, err)
	svc.saveWG.Wait()

	ob.mu.Lock()
	require.Len(t, ob.saveData, 2, "queued entry must reach the outbox store even if the item cache is unreadable")
	require.Equal(t, existing.ID, ob.saveData[0].ID)
	require.Equal(t, created.ID, ob.saveData[1].ItemID)
	ob.loadData = append([]coresync.OutboxMutation(nil), ob.saveData...)
	ob.mu.Unlock()
	svc.mu.Lock()
	require.Len(t, svc.cachePatches, 1, "unflushed patch is kept for retry")
	svc.mu.Unlock()

	fc.mu.Lock()
	fc.loadErr = nil
	fc.mu.Unlock()
	require.NoError(t, svc.Trash(context.Background(), "item-1"))

	items, outbox := vaultState(t, svc)
	require.Len(t, outbox, 3, "no duplicate outbox entries: existing, create, trash")
	require.Equal(t, created.ID, outbox[1].ItemID)
	require.Contains(t, items, created.ID, "retried create reaches the item cache")
	require.True(t, items["item-1"].Deleted)
	svc.mu.Lock()
	require.Empty(t, svc.cachePatches)
	svc.mu.Unlock()
}

// TestResidentBackToBackSyncedMutationsAreBothPersisted holds the cache writer
// so two remote-confirmed mutations are queued before either save runs. The
// older save is skipped as stale, so the newer one must carry both.
func TestResidentBackToBackSyncedMutationsAreBothPersisted(t *testing.T) {
	remote := &fakeRemote{createItem: vault.Item{ID: "remote-new", Name: "New", Type: vault.ItemTypeLogin}}
	svc := newMutationService(t, sessionResident, remote)

	svc.cacheSaveMu.Lock()
	_, err := svc.Create(context.Background(), vault.Item{Name: "New"})
	require.NoError(t, err)
	require.NoError(t, svc.Trash(context.Background(), "item-1"))
	svc.cacheSaveMu.Unlock()
	svc.saveWG.Wait()

	// Read the encrypted cache itself, not the resident state.
	snap, err := svc.vaultCache().Open(context.Background(), svc.cacheKey)
	require.NoError(t, err)
	byID := map[string]vault.Item{}
	for _, it := range snap.Items {
		byID[it.ID] = it
	}
	require.Contains(t, byID, "remote-new", "earlier synced create must not be lost")
	require.True(t, byID["item-1"].Deleted, "later synced trash must be persisted")
	require.Contains(t, byID, "item-2")
	require.Contains(t, byID, "item-3")
}

// TestCacheOnlyPatchesAreBoundToTheirSession: a flush belongs to the session
// (lifecycle) that queued it and is run with that session's key. It must take
// only its own session's patches and leave a later session's queued.
func TestCacheOnlyPatchesAreBoundToTheirSession(t *testing.T) {
	remote := &fakeRemote{trashErr: errRemoteDown, createErr: errRemoteDown}
	f := sessionFixture{items: mutationBase(), remote: remote}
	svc := f.service(t, sessionCacheOnly)

	svc.cacheSaveMu.Lock() // park every flush
	require.NoError(t, svc.Trash(context.Background(), "item-1"))
	svc.mu.Lock()
	oldSession := svc.lifecycle
	svc.mu.Unlock()
	require.NoError(t, svc.SoftLock(context.Background()))

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = []byte("another-cache-key-32-bytes-long!")
	svc.sessionMode = sessionCacheOnly
	svc.mu.Unlock()
	_, err := svc.Create(context.Background(), vault.Item{Name: "NewSession"})
	require.NoError(t, err)

	svc.mu.Lock()
	newSession := svc.lifecycle
	require.NotEqual(t, oldSession, newSession)
	require.Len(t, svc.cachePatches, 2)

	taken := svc.takeCachePatchesLocked(oldSession)
	require.Len(t, taken, 1, "the old session's flush takes only its own patch")
	require.Equal(t, oldSession, taken[0].lifecycle)
	require.Len(t, svc.cachePatches, 1)
	require.Equal(t, newSession, svc.cachePatches[0].lifecycle, "the new session's patch stays queued")
	svc.mu.Unlock()

	svc.cacheSaveMu.Unlock()
	svc.saveWG.Wait()
}
