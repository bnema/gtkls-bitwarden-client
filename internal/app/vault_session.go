package app

import (
	"context"

	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// sessionMode records where an unlocked session keeps decrypted vault state.
// It is decided exactly once, when the session is installed at unlock, and is
// never inferred from the contents of the resident fields afterwards.
//
//   - sessionResident (password unlock): decrypted items, folders, outbox and
//     conflicts are held in the Service and are authoritative.
//   - sessionCacheOnly (PIN unlock): resident plaintext is intentionally empty;
//     reads, sync and conflict resolution go through the encrypted cache.
//
// The zero value is sessionResident. The mode is only meaningful while the
// service is unlocked; lock and shutdown reset it.
type sessionMode int

const (
	sessionResident sessionMode = iota
	sessionCacheOnly
)

func (m sessionMode) cacheOnly() bool { return m == sessionCacheOnly }

// sessionView is what a read path captures from the session while holding
// s.mu. In resident mode it carries copies of the resident slices; in
// cache-only mode it carries only a copy of the cache key (no resident
// plaintext is read or copied). It is resolved into a vaultSnapshot outside
// the lock. The caller must call close to zero the key copy.
type sessionView struct {
	mode          sessionMode
	key           []byte
	items         []vault.Item
	outbox        []coresync.OutboxMutation
	pendingRemote []vault.Item
}

// vaultSnapshot is a point-in-time copy of the vault state a read path works
// on. PendingRemote holds the remote items staged by the last conflicting sync;
// it is only ever populated by resident sessions.
type vaultSnapshot struct {
	Items         []vault.Item
	Outbox        []coresync.OutboxMutation
	PendingRemote []vault.Item
}

// sessionViewLocked captures the session's storage mode and the state needed
// to read it. With deep set, resident items are deep-cloned so the snapshot
// shares no pointers with resident state. The caller MUST hold s.mu.
func (s *Service) sessionViewLocked(deep bool) sessionView {
	v := sessionView{mode: s.sessionMode}
	if v.mode.cacheOnly() {
		v.key = append([]byte(nil), s.cacheKey...)
		return v
	}
	if deep {
		v.items = cloneVaultItems(s.items)
		v.pendingRemote = cloneVaultItems(s.pendingRemoteItems)
	} else {
		v.items = append([]vault.Item(nil), s.items...)
	}
	v.outbox = append([]coresync.OutboxMutation(nil), s.outbox...)
	return v
}

// unlockedItems returns the session's vault items for a read path. Cache-only
// sessions read the encrypted cache; a cache read failure yields no items
// rather than an error. It returns ErrLocked if the service is not unlocked.
func (s *Service) unlockedItems(ctx context.Context) ([]vault.Item, error) {
	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	view := s.sessionViewLocked(false)
	s.mu.Unlock()
	defer view.close()

	snap, err := view.load(ctx, s.vaultCache())
	if err != nil {
		return nil, nil
	}
	return snap.Items, nil
}

// load resolves the view into a snapshot. Resident views are already
// materialized; cache-only views open the encrypted cache. It must be called
// without s.mu held.
func (v sessionView) load(ctx context.Context, vc vaultCache) (vaultSnapshot, error) {
	if !v.mode.cacheOnly() {
		return vaultSnapshot{Items: v.items, Outbox: v.outbox, PendingRemote: v.pendingRemote}, nil
	}
	snap, err := vc.Open(ctx, v.key)
	if err != nil {
		return vaultSnapshot{}, err
	}
	return vaultSnapshot{Items: snap.Items, Outbox: snap.Outbox}, nil
}

// close zeroes the key copy held by the view.
func (v sessionView) close() { clear(v.key) }
