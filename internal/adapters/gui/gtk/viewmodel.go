package gtk

import (
	"strings"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/display"
	coreerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
	corevault "github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
)

// RowViewModel represents a vault item row for display in a list.
// No sensitive secrets (passwords, TOTP, card codes, SSN, etc.) are included.
type RowViewModel struct {
	ID       string
	Title    string
	Subtitle string
	Badge    string
	Favorite bool
	Deleted  bool
	Conflict bool
	Pending  bool
}

// DetailViewModel represents a vault item detail view with safe display fields.
// Sensitive values are never included; presence is indicated by SecretPresent booleans.
type DetailViewModel struct {
	ID       string
	Name     string
	Type     string
	Favorite bool
	Deleted  bool

	// Login safe fields
	Username        string
	URIs            []string
	PasswordPresent bool
	TOTPPresent     bool

	// Card safe fields
	CardholderName string
	Brand          string
	Last4          string
	ExpMonth       string
	ExpYear        string
	CodePresent    bool

	// Identity safe fields
	IdentityName  string
	IdentityEmail string
	HasSSN        bool
	HasPassport   bool
	HasLicense    bool

	// Custom fields (non-hidden only)
	Fields     []DetailField
	SyncStatus string
}

// DetailField represents a single non-hidden custom field for detail display.
type DetailField struct {
	Name  string
	Value string
}

// StatusViewModel represents the sync/status bar state.
type StatusViewModel struct {
	Text          string
	Syncing       bool
	PendingCount  int
	ConflictCount int
	Offline       bool
	Error         string
}

// RowFromItem converts a vault Item to a safe RowViewModel.
func RowFromItem(item corevault.Item) RowViewModel {
	vm := RowViewModel{
		ID:       item.ID,
		Title:    item.Name,
		Favorite: item.Favorite,
		Deleted:  item.Deleted,
		Conflict: item.SyncStatus == corevault.SyncStatusConflict,
		Pending:  item.SyncStatus == corevault.SyncStatusPending,
		Subtitle: buildRowSubtitle(item),
	}
	vm.Badge = buildBadge(vm)
	return vm
}

// RowsFromScoredItems converts scored items to RowViewModels.
func RowsFromScoredItems(items []corevault.ScoredItem) []RowViewModel {
	if items == nil {
		return nil
	}
	vms := make([]RowViewModel, len(items))
	for i, si := range items {
		vms[i] = RowFromItem(si.Item)
	}
	return vms
}

// DetailFromItem converts a vault Item to a safe DetailViewModel.
func DetailFromItem(item corevault.Item) DetailViewModel {
	vm := DetailViewModel{
		ID:         item.ID,
		Name:       item.Name,
		Type:       string(item.Type),
		Favorite:   item.Favorite,
		Deleted:    item.Deleted,
		SyncStatus: string(item.SyncStatus),
	}

	switch item.Type {
	case corevault.ItemTypeLogin:
		if item.Login != nil {
			vm.Username = item.Login.Username
			for _, u := range item.Login.URIs {
				vm.URIs = append(vm.URIs, u.URI)
			}
			vm.PasswordPresent = item.Login.Password != ""
			vm.TOTPPresent = item.Login.TOTP != ""
		}
	case corevault.ItemTypeCard:
		if item.Card != nil {
			vm.CardholderName = item.Card.CardholderName
			vm.Brand = item.Card.Brand
			vm.Last4 = display.SafeLast4(item.Card.Number)
			vm.ExpMonth = item.Card.ExpMonth
			vm.ExpYear = item.Card.ExpYear
			vm.CodePresent = item.Card.Code != ""
		}
	case corevault.ItemTypeIdentity:
		if item.Identity != nil {
			vm.IdentityName = display.BuildIdentityName(item.Identity)
			vm.IdentityEmail = item.Identity.Email
			vm.HasSSN = item.Identity.SSN != ""
			vm.HasPassport = item.Identity.PassportNumber != ""
			vm.HasLicense = item.Identity.LicenseNumber != ""
		}
	}

	// Non-hidden custom fields only
	for _, f := range item.Fields {
		if !f.Hidden {
			vm.Fields = append(vm.Fields, DetailField{Name: f.Name, Value: f.Value})
		}
	}

	return vm
}

// StatusFromEvent maps an application event to a StatusViewModel.
func StatusFromEvent(evt in.Event) StatusViewModel {
	switch evt.Kind {
	case in.SyncChecking:
		return StatusViewModel{Text: "Checking for updates…", Syncing: true}
	case in.SyncUpdated:
		return StatusViewModel{Text: "Vault synced", Syncing: false}
	case in.SyncFailed:
		msg := coreerrors.ShortErrorText(evt.Message)
		if msg == coreerrors.ShortGenericError {
			msg = coreerrors.ShortSyncFailed
		}
		return StatusViewModel{Text: msg, Syncing: false, Error: msg}
	case in.MutationPending:
		return StatusViewModel{
			Text:         "Saving…",
			Syncing:      true,
			PendingCount: evt.Count,
		}
	case in.ConflictDetected:
		return StatusViewModel{
			Text:          "Conflict detected",
			Syncing:       false,
			ConflictCount: evt.Count,
		}
	case in.CacheLoaded:
		return StatusViewModel{Text: "Cache loaded — checking sync…", Offline: true, Syncing: true}
	case in.IndexReady:
		return StatusViewModel{Text: "Search ready", Offline: true}
	case in.Locked:
		return StatusViewModel{Text: "Locked", Offline: true}
	case in.Relocked:
		return StatusViewModel{Text: "Relocked", Offline: true}
	case in.Unlocking:
		return StatusViewModel{Text: "Unlocking…", Syncing: true}
	default:
		return StatusViewModel{Text: "", Syncing: false}
	}
}

// --- helpers ---

// buildRowSubtitle builds a safe one-line subtitle for a vault item row.
func buildRowSubtitle(item corevault.Item) string {
	return display.BuildRowSubtitle(item)
}

// buildBadge returns a short text badge for the row item state.
func buildBadge(vm RowViewModel) string {
	var badges []string
	if vm.Deleted {
		badges = append(badges, "Deleted")
	}
	if vm.Pending {
		badges = append(badges, "Pending")
	}
	if vm.Conflict {
		badges = append(badges, "Conflict")
	}
	if vm.Favorite {
		badges = append(badges, "★")
	}
	return strings.Join(badges, " ")
}
