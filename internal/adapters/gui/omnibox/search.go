package omnibox

import (
	"net/url"
	"strings"

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
			return ActionCopyPassword // open_url not wired yet; fallback safe
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
	}
	r.Badge = buildBadge(item)
	return r
}

// buildRowSubtitle builds a safe one-line subtitle for a vault item row.
func buildRowSubtitle(item vault.Item) string {
	switch item.Type {
	case vault.ItemTypeLogin:
		if item.Login == nil {
			return ""
		}
		parts := make([]string, 0, 2)
		if item.Login.Username != "" {
			parts = append(parts, item.Login.Username)
		}
		if len(item.Login.URIs) > 0 {
			parts = append(parts, safeURI(item.Login.URIs[0].URI))
		}
		return strings.Join(parts, " — ")

	case vault.ItemTypeSecureNote:
		return "Secure note"

	case vault.ItemTypeCard:
		if item.Card == nil {
			return ""
		}
		parts := make([]string, 0, 2)
		if item.Card.Brand != "" {
			parts = append(parts, item.Card.Brand)
		}
		if last4 := safeLast4(item.Card.Number); last4 != "" {
			parts = append(parts, "•••• "+last4)
		}
		return strings.Join(parts, " ")

	case vault.ItemTypeIdentity:
		if item.Identity == nil {
			return ""
		}
		parts := make([]string, 0, 4)
		if item.Identity.FirstName != "" {
			parts = append(parts, item.Identity.FirstName)
		}
		if item.Identity.LastName != "" {
			parts = append(parts, item.Identity.LastName)
		}
		if item.Identity.Email != "" {
			parts = append(parts, item.Identity.Email)
		}
		if item.Identity.Username != "" {
			parts = append(parts, item.Identity.Username)
		}
		return strings.Join(parts, " — ")

	default:
		return ""
	}
}

// safeURI attempts to extract just the host from a URI string.
func safeURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
			return raw[:idx]
		}
		return raw
	}
	return u.Host
}

// safeLast4 returns the last 4 characters of a card number if it is at least
// 4 characters long.
func safeLast4(number string) string {
	if len(number) < 4 {
		return ""
	}
	return number[len(number)-4:]
}
