package omnibox

import (
	"strings"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/gui/display"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
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
		ID:       item.ID,
		Title:    item.Name,
		Deleted:  item.Deleted,
		Conflict: item.SyncStatus == vault.SyncStatusConflict,
		Pending:  item.SyncStatus == vault.SyncStatusPending,
		Subtitle: buildRowSubtitle(item),
		Type:     string(item.Type),
	}
	r.Badge = buildBadge(item)
	return r
}

// buildRowSubtitle builds a safe one-line subtitle for a vault item row.
func buildRowSubtitle(item vault.Item) string {
	return display.BuildRowSubtitle(item)
}
