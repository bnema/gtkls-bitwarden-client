package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

// mutation is the input of one vault mutation. Create and Update carry the
// full item; Trash, Restore and Delete only identify their target.
type mutation struct {
	ID   string
	Item vault.Item
}

// mutationOutcome says how a mutation ended: confirmed by the remote
// (SyncStatusSynced, remote holds the remote's resulting item) or queued in
// the outbox (SyncStatusPending, remote unused).
type mutationOutcome struct {
	status vault.SyncStatus
	remote vault.Item
}

// mutationSpec defines one mutation kind exactly once: how to call the remote,
// how to apply it to a list of items, and how to encode/decode its outbox
// payload. Service.applyMutation runs the shared flow and Service.replayOutbox
// replays queued mutations from the same definitions.
type mutationSpec struct {
	kind coresync.MutationKind

	// operation is the log operation of the whole mutation;
	// remoteLocalOperation names the warning logged when the remote call
	// succeeded but the service relocked before the local update.
	operation            string
	remoteLocalOperation string
	syncedMessage        string
	pendingMessage       string

	// returnsItem reports whether the public method returns the resulting
	// item (and whether a missing item ID means "no result" when logging).
	returnsItem bool

	// call performs the remote operation. The returned item is zero for kinds
	// that return none.
	call func(ctx context.Context, r out.RemoteItems, m mutation) (vault.Item, error)

	// stage prepares m for queueing offline (assigns IDs, stamps revision).
	// nil means m is queued unchanged.
	stage func(m mutation, now time.Time, newLocalID func() string) mutation

	// apply applies m to items for the given outcome and returns the new list
	// plus the resulting item (zero if the kind has none). It must not modify
	// items in place.
	apply func(items []vault.Item, m mutation, o mutationOutcome) ([]vault.Item, vault.Item)

	// encode and decode convert m to and from its outbox payload. decode gets
	// the outbox mutation's item ID.
	encode func(m mutation) ([]byte, error)
	decode func(itemID string, payload []byte) (mutation, error)
}

// itemID is the item the outbox entry for m is about.
func (m mutation) itemID() string {
	if m.Item.ID != "" {
		return m.Item.ID
	}
	return m.ID
}

func encodeItemPayload(m mutation) ([]byte, error) { return json.Marshal(m.Item) }

func decodeItemPayload(itemID string, payload []byte) (mutation, error) {
	var item vault.Item
	if err := json.Unmarshal(payload, &item); err != nil {
		return mutation{}, err
	}
	return mutation{ID: itemID, Item: item}, nil
}

func encodeIDPayload(m mutation) ([]byte, error) {
	return json.Marshal(map[string]string{"id": m.ID})
}

func decodeIDPayload(itemID string, _ []byte) (mutation, error) {
	return mutation{ID: itemID}, nil
}

// applyItemUpsert is the local effect of create and update: the resulting
// item (the remote's when synced, the queued one when pending) replaces or
// joins the list.
func applyItemUpsert(items []vault.Item, m mutation, o mutationOutcome) ([]vault.Item, vault.Item) {
	item := m.Item
	if o.status == vault.SyncStatusSynced {
		item = o.remote
	}
	item.SyncStatus = o.status
	key := m.ID
	if key == "" {
		key = item.ID
	}
	return upsertVaultItemAs(items, key, item), item
}

// setVaultItemDeleted returns items with the item id marked deleted (or not)
// and carrying status, plus that item (zero if absent).
func setVaultItemDeleted(items []vault.Item, id string, deleted bool, status vault.SyncStatus) ([]vault.Item, vault.Item) {
	out := make([]vault.Item, len(items))
	copy(out, items)
	for i := range out {
		if out[i].ID == id {
			out[i].Deleted = deleted
			out[i].SyncStatus = status
			return out, out[i]
		}
	}
	return out, vault.Item{}
}

var createMutation = &mutationSpec{
	kind:                 coresync.MutationCreate,
	operation:            "mutation_create",
	remoteLocalOperation: "remote_create_local_update",
	syncedMessage:        "item created remotely",
	pendingMessage:       "item queued for creation",
	returnsItem:          true,
	call: func(ctx context.Context, r out.RemoteItems, m mutation) (vault.Item, error) {
		return r.Create(ctx, m.Item)
	},
	stage: func(m mutation, now time.Time, newLocalID func() string) mutation {
		if m.Item.ID == "" {
			m.Item.ID = newLocalID()
		}
		m.Item.SyncStatus = vault.SyncStatusPending
		m.Item.RevisionDate = now
		return m
	},
	apply:  applyItemUpsert,
	encode: encodeItemPayload,
	decode: decodeItemPayload,
}

var updateMutation = &mutationSpec{
	kind:                 coresync.MutationUpdate,
	operation:            "mutation_update",
	remoteLocalOperation: "remote_update_local_update",
	syncedMessage:        "item updated remotely",
	pendingMessage:       "item queued for update",
	returnsItem:          true,
	call: func(ctx context.Context, r out.RemoteItems, m mutation) (vault.Item, error) {
		return r.Update(ctx, m.ID, m.Item)
	},
	stage: func(m mutation, now time.Time, _ func() string) mutation {
		m.Item.ID = m.ID
		m.Item.SyncStatus = vault.SyncStatusPending
		m.Item.RevisionDate = now
		return m
	},
	apply:  applyItemUpsert,
	encode: encodeItemPayload,
	decode: decodeItemPayload,
}

var trashMutation = &mutationSpec{
	kind:                 coresync.MutationTrash,
	operation:            "mutation_trash",
	remoteLocalOperation: "remote_trash_local_update",
	syncedMessage:        "item trashed remotely",
	pendingMessage:       "item queued for trash",
	call: func(ctx context.Context, r out.RemoteItems, m mutation) (vault.Item, error) {
		return vault.Item{}, r.Trash(ctx, m.ID)
	},
	apply: func(items []vault.Item, m mutation, o mutationOutcome) ([]vault.Item, vault.Item) {
		return setVaultItemDeleted(items, m.ID, true, o.status)
	},
	encode: encodeIDPayload,
	decode: decodeIDPayload,
}

var restoreMutation = &mutationSpec{
	kind:                 coresync.MutationRestore,
	operation:            "mutation_restore",
	remoteLocalOperation: "remote_restore_local_update",
	syncedMessage:        "item restored remotely",
	pendingMessage:       "item queued for restore",
	returnsItem:          true,
	call: func(ctx context.Context, r out.RemoteItems, m mutation) (vault.Item, error) {
		return r.Restore(ctx, m.ID)
	},
	apply: func(items []vault.Item, m mutation, o mutationOutcome) ([]vault.Item, vault.Item) {
		if o.status == vault.SyncStatusSynced {
			item := o.remote
			item.Deleted = false
			item.SyncStatus = o.status
			return upsertVaultItemAs(items, m.ID, item), item
		}
		return setVaultItemDeleted(items, m.ID, false, o.status)
	},
	encode: encodeIDPayload,
	decode: decodeIDPayload,
}

var deleteMutation = &mutationSpec{
	kind:                 coresync.MutationDelete,
	operation:            "mutation_delete",
	remoteLocalOperation: "remote_delete_local_update",
	syncedMessage:        "item deleted remotely",
	pendingMessage:       "item queued for deletion",
	call: func(ctx context.Context, r out.RemoteItems, m mutation) (vault.Item, error) {
		return vault.Item{}, r.Delete(ctx, m.ID)
	},
	apply: func(items []vault.Item, m mutation, _ mutationOutcome) ([]vault.Item, vault.Item) {
		return removeVaultItem(items, m.ID), vault.Item{}
	},
	encode: encodeIDPayload,
	decode: decodeIDPayload,
}

// mutationSpecFor returns the definition of an outbox mutation kind.
func mutationSpecFor(kind coresync.MutationKind) (*mutationSpec, bool) {
	switch kind {
	case coresync.MutationCreate:
		return createMutation, true
	case coresync.MutationUpdate:
		return updateMutation, true
	case coresync.MutationTrash:
		return trashMutation, true
	case coresync.MutationRestore:
		return restoreMutation, true
	case coresync.MutationDelete:
		return deleteMutation, true
	default:
		return nil, false
	}
}

// applyMutation is the one flow behind Create, Update, Trash, Restore and
// Delete. It tries the remote first; on success the confirmed result is
// applied locally and persisted, otherwise (no remote, or any remote error)
// the mutation is queued in the outbox and applied locally as pending.
func (s *Service) applyMutation(ctx context.Context, spec *mutationSpec, m mutation) (retItem vault.Item, retErr error) {
	log, started := logAppServiceStart(ctx, spec.operation)
	defer func() {
		count := 0
		if retErr == nil && (!spec.returnsItem || retItem.ID != "") {
			count = 1
		}
		logAppServiceFinishCount(log, started, retErr, count)
	}()

	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return vault.Item{}, err
	}
	s.mu.Unlock()

	if s.deps.Remote != nil {
		remoteItem, err := spec.call(ctx, s.deps.Remote, m)
		if err == nil {
			return s.commitSynced(ctx, spec, m, remoteItem)
		}
	}
	return s.queuePending(ctx, spec, m)
}

// commitSynced applies a remote-confirmed mutation locally. Resident sessions
// update the resident items; cache-only sessions keep resident state empty and
// only patch the encrypted cache.
func (s *Service) commitSynced(ctx context.Context, spec *mutationSpec, m mutation, remoteItem vault.Item) (vault.Item, error) {
	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		logRemoteSuccessLocalLocked(ctx, spec.remoteLocalOperation)
		return vault.Item{}, err
	}
	outcome := mutationOutcome{status: vault.SyncStatusSynced, remote: remoteItem}
	result := s.applyResidentLocked(spec, m, outcome)
	s.rebuildIndexLocked()
	if s.sessionMode.cacheOnly() {
		s.saveCacheMutationAsyncLocked(ctx, func(d *decryptedCacheSnapshot) {
			d.Items, _ = spec.apply(d.Items, m, outcome)
		})
	} else {
		// Resident items are authoritative: unlock installs the whole cache
		// into s.items and sync replaces both together, so the cache never
		// holds more than s.items. Persist them as a full snapshot, which a
		// newer snapshot may safely supersede (a queued patch would be
		// skipped as stale instead). The offline path already persists this
		// way through appendOutboxLocked.
		s.saveCacheAsyncLocked(ctx)
	}
	s.mu.Unlock()
	s.emit(SyncUpdated, spec.syncedMessage)
	return result, nil
}

// queuePending records the mutation in the outbox and applies it locally as
// pending. Resident sessions hold the outbox and items in memory; cache-only
// sessions add both to the encrypted cache instead.
func (s *Service) queuePending(ctx context.Context, spec *mutationSpec, m mutation) (vault.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureUnlocked(); err != nil {
		return vault.Item{}, err
	}

	if spec.stage != nil {
		m = spec.stage(m, s.now(), func() string {
			s.outboxSeq++
			return fmt.Sprintf("local-%d-%d", s.now().UnixNano(), s.outboxSeq)
		})
	}
	payload, err := spec.encode(m)
	if err != nil {
		return vault.Item{}, fmt.Errorf("app: marshal %s payload: %w", spec.kind, err)
	}
	queued := s.newOutboxMutationLocked(spec.kind, m.itemID(), payload)
	outcome := mutationOutcome{status: vault.SyncStatusPending}

	if s.sessionMode.cacheOnly() {
		s.saveCacheMutationAsyncLocked(ctx, func(d *decryptedCacheSnapshot) {
			d.Items, _ = spec.apply(d.Items, m, outcome)
			d.Outbox = append(d.Outbox, queued)
		})
	} else {
		s.appendOutboxLocked(ctx, queued)
	}
	result := s.applyResidentLocked(spec, m, outcome)
	s.rebuildIndexLocked()
	s.emit(MutationPending, spec.pendingMessage)
	return result, nil
}

// applyResidentLocked applies m to the resident items of a resident session
// and returns the resulting item. A cache-only session has no resident items:
// they stay untouched and the result is computed against an empty list (so
// kinds that only flag an existing item, such as a pending restore, return no
// item). The caller MUST hold s.mu.
func (s *Service) applyResidentLocked(spec *mutationSpec, m mutation, o mutationOutcome) vault.Item {
	if s.sessionMode.cacheOnly() {
		_, result := spec.apply(nil, m, o)
		return result
	}
	var result vault.Item
	s.items, result = spec.apply(s.items, m, o)
	return result
}

// replayMutation replays one outbox mutation against the remote using the
// shared mutation definitions.
func (s *Service) replayMutation(ctx context.Context, m coresync.OutboxMutation) error {
	spec, ok := mutationSpecFor(m.Kind)
	if !ok {
		return fmt.Errorf("%w: unknown mutation kind %s", cerrors.ErrUnsupported, m.Kind)
	}
	decoded, err := spec.decode(m.ItemID, m.Payload)
	if err != nil {
		return fmt.Errorf("replay unmarshal: %w", err)
	}
	if _, err := spec.call(ctx, s.deps.Remote, decoded); err != nil {
		return fmt.Errorf("replay %s: %w", m.Kind, err)
	}
	return nil
}
