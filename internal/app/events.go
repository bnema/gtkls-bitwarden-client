package app

import "github.com/bnema/gtkls-bitwarden-client/internal/ports/in"

// Event is a domain event emitted by the application layer.
type Event = in.Event

// EventKind categorises events emitted by the application layer.
type EventKind = in.EventKind

const (
	Locked           EventKind = in.Locked
	Unlocking        EventKind = in.Unlocking
	CacheLoaded      EventKind = in.CacheLoaded
	IndexReady       EventKind = in.IndexReady
	SyncChecking     EventKind = in.SyncChecking
	SyncUpdated      EventKind = in.SyncUpdated
	SyncFailed       EventKind = in.SyncFailed
	MutationPending  EventKind = in.MutationPending
	ConflictDetected EventKind = in.ConflictDetected
	Relocked         EventKind = in.Relocked
)
