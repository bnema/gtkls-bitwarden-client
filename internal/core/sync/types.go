package sync

import "time"

// MutationKind represents the type of a local mutation.
type MutationKind string

const (
	MutationCreate       MutationKind = "create"
	MutationUpdate       MutationKind = "update"
	MutationTrash        MutationKind = "trash"
	MutationRestore      MutationKind = "restore"
	MutationDelete       MutationKind = "delete"
	MutationFolderChange MutationKind = "folder_change"
	MutationAttachment   MutationKind = "attachment"
)

// OutboxMutation represents a pending local mutation to be synced.
type OutboxMutation struct {
	ID           string
	Kind         MutationKind
	ItemID       string
	BaseRevision string
	CreatedAt    time.Time
	Payload      []byte
}

// RemoteChange represents a change detected on the remote server.
type RemoteChange struct {
	ItemID   string
	Revision string
	Deleted  bool
}
