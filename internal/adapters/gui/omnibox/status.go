package omnibox

import "github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"

// Status represents the sync/status bar state.
type Status struct {
	Text          string
	Syncing       bool
	Offline       bool
	PendingCount  int
	ConflictCount int
	Error         string
}

// StatusFromEvent maps an application event to a Status.
func StatusFromEvent(evt in.Event) Status {
	switch evt.Kind {
	case in.SyncChecking:
		return Status{Text: "Checking for updates…", Syncing: true}
	case in.SyncUpdated:
		return Status{Text: "Vault updated", Syncing: false}
	case in.SyncFailed:
		msg := evt.Message
		if msg == "" {
			msg = "Sync failed"
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
		return Status{Text: "Cache loaded", Offline: true}
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
