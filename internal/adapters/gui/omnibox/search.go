package omnibox

import (
	"strings"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/display"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// RowsFromItems converts vault Items to safe Row slices.
func RowsFromItems(items []vault.Item) []Row {
	if items == nil {
		return nil
	}
	rows := make([]Row, len(items))
	for i, item := range items {
		rows[i] = rowFromItem(item)
	}
	return rows
}

// RowsFromScored converts scored items to safe Row slices.
func RowsFromScored(scored []vault.ScoredItem) []Row {
	if scored == nil {
		return nil
	}
	rows := make([]Row, len(scored))
	for i, si := range scored {
		rows[i] = rowFromItem(si.Item)
	}
	return rows
}

// RowsWithConflictPlaceholders appends safe placeholder rows for conflicts that
// are not represented by an item row. It deliberately avoids item names and raw
// IDs in displayed text because conflict snapshots may be the only data loaded.
func RowsWithConflictPlaceholders(rows []Row, conflicts []coresync.Conflict) []Row {
	if len(conflicts) == 0 {
		return rows
	}
	representedConflictIDs := make(map[string]int, len(rows))
	representedItemIDs := make(map[string]int, len(rows))
	for i, row := range rows {
		if row.ConflictID != "" {
			representedConflictIDs[row.ConflictID] = i
		}
		if row.ID != "" {
			representedItemIDs[row.ID] = i
		}
	}
	for _, conflict := range conflicts {
		if conflict.ID == "" {
			continue
		}
		if idx, ok := representedConflictIDs[conflict.ID]; ok {
			rows[idx] = markRowConflict(rows[idx], conflict)
			continue
		}
		if idx, ok := representedItemIDs[conflict.ItemID]; ok {
			rows[idx] = markRowConflict(rows[idx], conflict)
			representedConflictIDs[conflict.ID] = idx
			continue
		}
		rows = append(rows, rowFromConflict(conflict))
		idx := len(rows) - 1
		representedConflictIDs[conflict.ID] = idx
		representedItemIDs[conflict.ItemID] = idx
	}
	return rows
}

func markRowConflict(row Row, conflict coresync.Conflict) Row {
	row.Conflict = true
	if row.ConflictID == "" {
		row.ConflictID = conflict.ID
	}
	if !strings.Contains(row.Badge, "Conflict") {
		if row.Badge == "" {
			row.Badge = "Conflict"
		} else {
			row.Badge += " Conflict"
		}
	}
	return row
}

func rowFromConflict(conflict coresync.Conflict) Row {
	return Row{
		ID:         conflict.ItemID,
		Title:      "Conflicted item",
		Subtitle:   conflictReasonSubtitle(conflict.Reason),
		Badge:      "Conflict",
		Conflict:   true,
		ConflictID: conflict.ID,
	}
}

func conflictReasonSubtitle(reason coresync.ConflictReason) string {
	switch reason {
	case coresync.ConflictBothModified:
		return "Local and remote changes both exist"
	case coresync.ConflictRemoteDeleted:
		return "Remote item was deleted"
	case coresync.ConflictLocalDeletedRemoteModified:
		return "Local delete conflicts with remote changes"
	default:
		return "Local and remote changes conflict"
	}
}

// PrimaryActionFor returns the Action to perform when the user activates a row.
// It respects cfg.Actions.DefaultPrimaryAction with a safe fallback to
// ActionCopyPassword.
func PrimaryActionFor(row Row, cfg *config.Config) Action {
	if cfg != nil {
		switch cfg.Actions.DefaultPrimaryAction {
		case config.ActionCopyUsername:
			return ActionCopyUsername
		case config.ActionOpenDetail:
			return ActionOpenDetail
		case config.ActionCopyPassword:
			return ActionCopyPassword
		case config.ActionOpenURL:
			// TODO: open_url is not yet implemented. Return safe fallback.
			return ActionCopyPassword
		}
	}
	return ActionCopyPassword
}

// SearchEnterActionForModifiers returns the action for Enter in search mode.
// Ctrl+Enter is reserved for opening details; Alt+Enter copies the username;
// plain Enter keeps the configured primary action.
func SearchEnterActionForModifiers(row Row, cfg *config.Config, ctrlPressed, altPressed bool) Action {
	if row.Conflict && row.ConflictID != "" && row.Type == "" {
		return ActionOpenDetail
	}
	if ctrlPressed {
		return ActionOpenDetail
	}
	if altPressed {
		return ActionCopyUsername
	}
	return PrimaryActionFor(row, cfg)
}

// SearchCopyOptions returns nil-safe copy behavior for search shortcuts.
func SearchCopyOptions(cfg *config.Config) (time.Duration, bool) {
	if cfg == nil {
		return 0, false
	}
	return primaryActionClipboardTTL(cfg), cfg.Actions.CloseAfterCopy
}

// buildBadge returns a short text badge for the row item state.
func buildBadge(item vault.Item) string {
	var badges []string
	if item.Deleted {
		badges = append(badges, "Deleted")
	}
	if item.SyncStatus == vault.SyncStatusPending {
		badges = append(badges, "Pending")
	}
	if item.SyncStatus == vault.SyncStatusConflict {
		badges = append(badges, "Conflict")
	}
	if item.Favorite {
		badges = append(badges, "★")
	}
	return strings.Join(badges, " ")
}

// rowFromItem converts a vault Item to a safe Row.
// Sensitive data (passwords, TOTP, card codes, SSN, passport, license) is
// never included in the subtitle.
func rowFromItem(item vault.Item) Row {
	r := Row{
		ID:         item.ID,
		Title:      item.Name,
		Deleted:    item.Deleted,
		Conflict:   item.SyncStatus == vault.SyncStatusConflict,
		ConflictID: item.ConflictID,
		Pending:    item.SyncStatus == vault.SyncStatusPending,
		Subtitle:   buildRowSubtitle(item),
		Type:       string(item.Type),
	}
	r.Badge = buildBadge(item)
	return r
}

// buildRowSubtitle builds a safe one-line subtitle for a vault item row.
func buildRowSubtitle(item vault.Item) string {
	return display.BuildRowSubtitle(item)
}
