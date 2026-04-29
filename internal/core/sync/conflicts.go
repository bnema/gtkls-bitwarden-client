package sync

// ConflictReason describes why a conflict occurred.
type ConflictReason string

const (
	ConflictBothModified               ConflictReason = "both_modified"
	ConflictRemoteDeleted              ConflictReason = "remote_deleted"
	ConflictLocalDeletedRemoteModified ConflictReason = "local_deleted_remote_modified"
)

// ConflictResolution describes how a conflict can be resolved.
type ConflictResolution string

const (
	ResolutionKeepLocal      ConflictResolution = "keep_local"
	ResolutionKeepRemote     ConflictResolution = "keep_remote"
	ResolutionDuplicateLocal ConflictResolution = "duplicate_local"
)

// Conflict represents a sync conflict between a local mutation and a remote change.
type Conflict struct {
	ID         string
	ItemID     string
	MutationID string
	Reason     ConflictReason
}

// isLocalNonDelete returns true if the mutation is not a delete or trash.
func isLocalNonDelete(kind MutationKind) bool {
	return kind != MutationDelete && kind != MutationTrash
}

// isLocalDeleteOrTrash returns true if the mutation is a delete or trash.
func isLocalDeleteOrTrash(kind MutationKind) bool {
	return kind == MutationDelete || kind == MutationTrash
}

// DetectConflicts compares local mutations against remote changes and returns
// any conflicts found.
//
// Rules:
//   - Same item, local non-delete, remote changed not deleted => both_modified
//   - Same item, local non-delete, remote deleted => remote_deleted
//   - Same item, local delete/trash, remote changed not deleted => local_deleted_remote_modified
//   - Different items => no conflict
func DetectConflicts(local []OutboxMutation, remote []RemoteChange) []Conflict {
	var conflicts []Conflict

	for _, l := range local {
		for _, r := range remote {
			if l.ItemID != r.ItemID {
				continue // different items, no conflict
			}

			switch {
			case isLocalNonDelete(l.Kind) && !r.Deleted:
				conflicts = append(conflicts, Conflict{
					ID:         l.ID + "_" + r.ItemID,
					ItemID:     l.ItemID,
					MutationID: l.ID,
					Reason:     ConflictBothModified,
				})
			case isLocalNonDelete(l.Kind) && r.Deleted:
				conflicts = append(conflicts, Conflict{
					ID:         l.ID + "_" + r.ItemID,
					ItemID:     l.ItemID,
					MutationID: l.ID,
					Reason:     ConflictRemoteDeleted,
				})
			case isLocalDeleteOrTrash(l.Kind) && !r.Deleted:
				conflicts = append(conflicts, Conflict{
					ID:         l.ID + "_" + r.ItemID,
					ItemID:     l.ItemID,
					MutationID: l.ID,
					Reason:     ConflictLocalDeletedRemoteModified,
				})
			}
		}
	}

	return conflicts
}
