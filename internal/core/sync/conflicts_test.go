package sync

import (
	"testing"
	"time"
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
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Reason != ConflictBothModified {
		t.Errorf("expected both_modified, got %s", conflicts[0].Reason)
	}
	if conflicts[0].ItemID != "item-1" {
		t.Errorf("expected item-1, got %s", conflicts[0].ItemID)
	}
	if conflicts[0].MutationID != "m1" {
		t.Errorf("expected m1, got %s", conflicts[0].MutationID)
	}
}

func TestDetectConflictsRemoteDeleted(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}
	remote := []RemoteChange{mkRemote("item-1", "rev2", true)}

	conflicts := DetectConflicts(local, remote)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Reason != ConflictRemoteDeleted {
		t.Errorf("expected remote_deleted, got %s", conflicts[0].Reason)
	}
}

func TestDetectConflictsLocalDeletedRemoteModified(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationDelete)}
	remote := []RemoteChange{mkRemote("item-1", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Reason != ConflictLocalDeletedRemoteModified {
		t.Errorf("expected local_deleted_remote_modified, got %s", conflicts[0].Reason)
	}
}

func TestDetectConflictsLocalTrashRemoteModified(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationTrash)}
	remote := []RemoteChange{mkRemote("item-1", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Reason != ConflictLocalDeletedRemoteModified {
		t.Errorf("expected local_deleted_remote_modified, got %s", conflicts[0].Reason)
	}
}

func TestDetectConflictsDifferentItemsNoConflict(t *testing.T) {
	local := []OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}
	remote := []RemoteChange{mkRemote("item-2", "rev2", false)}

	conflicts := DetectConflicts(local, remote)
	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts for different items, got %d", len(conflicts))
	}
}

func TestDetectConflictsEmptyInputs(t *testing.T) {
	conflicts := DetectConflicts(nil, nil)
	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts for empty inputs, got %d", len(conflicts))
	}

	conflicts = DetectConflicts([]OutboxMutation{mkMutation("m1", "item-1", MutationUpdate)}, nil)
	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts when no remote changes, got %d", len(conflicts))
	}

	conflicts = DetectConflicts(nil, []RemoteChange{mkRemote("item-1", "rev2", false)})
	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts when no local mutations, got %d", len(conflicts))
	}
}
