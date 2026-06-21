package sync

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func mkMutation(id, itemID string, kind MutationKind) OutboxMutation {
	return OutboxMutation{
		ID:           id,
		Kind:         kind,
		ItemID:       itemID,
		BaseRevision: "rev1",
		CreatedAt:    time.Now(),
	}
}

func mkRemote(itemID, revision string, deleted bool) RemoteChange {
	return RemoteChange{
		ItemID:   itemID,
		Revision: revision,
		Deleted:  deleted,
	}
}

func TestDetectConflictsBothModified(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}
	remote := []RemoteChange{mkRemote("item-1", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	require.Len(t, conflicts, 1)
	require.Equal(t, ConflictBothModified, conflicts[0].Reason)
	require.Equal(t, "item-1", conflicts[0].ItemID)
	require.Equal(t, "m1", conflicts[0].MutationID)
}

func TestDetectConflictsMatchingBaseRevisionNoConflict(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}
	local[0].BaseRevision = "rev2"
	remote := []RemoteChange{mkRemote("item-1", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	require.Empty(t, conflicts)
}

func TestDetectConflictsRemoteDeleted(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}
	remote := []RemoteChange{mkRemote("item-1", "rev2", true)}

	conflicts := DetectConflicts(local, remote)
	require.Len(t, conflicts, 1)
	require.Equal(t, ConflictRemoteDeleted, conflicts[0].Reason)
}

func TestDetectConflictsLocalDeletedRemoteModified(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationDelete)}
	remote := []RemoteChange{mkRemote("item-1", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	require.Len(t, conflicts, 1)
	require.Equal(t, ConflictLocalDeletedRemoteModified, conflicts[0].Reason)
}

func TestDetectConflictsLocalTrashRemoteModified(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationTrash)}
	remote := []RemoteChange{mkRemote("item-1", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	require.Len(t, conflicts, 1)
	require.Equal(t, ConflictLocalDeletedRemoteModified, conflicts[0].Reason)
}

func TestDetectConflictsDifferentItemsNoConflict(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}
	remote := []RemoteChange{mkRemote("item-2", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	require.Empty(t, conflicts)
}

func TestDetectConflictsEmptyInputs(t *testing.T) {
	conflicts := DetectConflicts(nil, nil)
	require.Empty(t, conflicts)

	conflicts = DetectConflicts([]OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}, nil)
	require.Empty(t, conflicts)

	conflicts = DetectConflicts(nil, []RemoteChange{mkRemote("item-1", "rev2", false)})
	require.Empty(t, conflicts)
}
