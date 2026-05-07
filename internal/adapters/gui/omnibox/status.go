package omnibox

import (
	"fmt"

	coreerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

// Status represents the sync/status bar state.
type Status struct {
	Text          string
	Syncing       bool
	Offline       bool
	PendingCount  int
	ConflictCount int
	ItemCount     int
	Error         string
}

// StatusFromEvent maps an application event to a Status.
func StatusFromEvent(evt in.Event) Status {
	switch evt.Kind {
	case in.SyncChecking:
		return Status{Text: "Checking for updates…", Syncing: true}
	case in.SyncUpdated:
		return Status{Text: "Vault synced", Syncing: false}
	case in.SyncFailed:
		msg := coreerrors.ShortErrorText(evt.Message)
		if msg == coreerrors.ShortGenericError {
			msg = coreerrors.ShortSyncFailed
		}
		return Status{Text: msg, Syncing: false, Error: msg}
	case in.MutationPending:
		return Status{
			Text:         "Saving…",
			Syncing:      true,
			PendingCount: evt.Count,
		}
	case in.ConflictDetected:
		return Status{
			Text:          "Conflict detected",
			Syncing:       false,
			ConflictCount: evt.Count,
		}
	case in.CacheLoaded:
		return Status{Text: "Cache loaded — checking sync…", Offline: true, Syncing: true}
	case in.IndexReady:
		return Status{Text: "Search ready", Offline: true}
	case in.Locked:
		return Status{Text: "Locked", Offline: true}
	case in.Relocked:
		return Status{Text: "Relocked", Offline: true}
	case in.Unlocking:
		return Status{Text: "Unlocking…", Syncing: true}
	default:
		return Status{Text: "", Syncing: false}
	}
}

// ReadyStatus returns a safe status summary for the currently loaded vault.
// It intentionally exposes only aggregate counts, never item names or fields.
func ReadyStatus(itemCount int) Status {
	return Status{Text: fmt.Sprintf("Vault ready — %d %s", itemCount, plural(itemCount, "item", "items")), ItemCount: itemCount}
}

// EmptyRowsText returns the placeholder shown when the current search list has
// no rows. The query text is deliberately not echoed because search terms may
// contain domains, emails, usernames, or other sensitive fragments.
func EmptyRowsText(query string, status Status) string {
	switch {
	case query != "":
		return "No matching items"
	case status.Syncing:
		return "Loading vault…"
	default:
		return "No vault items loaded yet"
	}
}

// ShouldRefreshRowsOnEvent reports whether a backend event means the visible
// search results may now be stale and should be reloaded from the service.
func ShouldRefreshRowsOnEvent(kind in.EventKind) bool {
	return kind == in.IndexReady || kind == in.SyncUpdated
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
