package gtk

import (
	"net/url"
	"strings"

	corevault "github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
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
			vm.Last4 = safeLast4(item.Card.Number)
			vm.ExpMonth = item.Card.ExpMonth
			vm.ExpYear = item.Card.ExpYear
			vm.CodePresent = item.Card.Code != ""
		}
	case corevault.ItemTypeIdentity:
		if item.Identity != nil {
			parts := make([]string, 0, 5)
			if item.Identity.Title != "" {
				parts = append(parts, item.Identity.Title)
			}
			if item.Identity.FirstName != "" {
				parts = append(parts, item.Identity.FirstName)
			}
			if item.Identity.MiddleName != "" {
				parts = append(parts, item.Identity.MiddleName)
			}
			if item.Identity.LastName != "" {
				parts = append(parts, item.Identity.LastName)
			}
			vm.IdentityName = strings.Join(parts, " ")
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
		return StatusViewModel{Text: "Vault updated", Syncing: false}
	case in.SyncFailed:
		msg := evt.Message
		if msg == "" {
			msg = "Sync failed"
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
	default:
		return StatusViewModel{Text: "", Syncing: false}
	}
}

// --- helpers ---

// buildRowSubtitle builds a safe one-line subtitle for a vault item row.
// Sensitive data (passwords, TOTP, card codes, SSN, passport, license) is never included.
func buildRowSubtitle(item corevault.Item) string {
	switch item.Type {
	case corevault.ItemTypeLogin:
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

	case corevault.ItemTypeSecureNote:
		return "Secure note"

	case corevault.ItemTypeCard:
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

	case corevault.ItemTypeIdentity:
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
// If parsing fails, the raw URI is returned with query/fragment stripped.
func safeURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Fallback: strip query and fragment manually
		if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
			return raw[:idx]
		}
		return raw
	}
	return u.Host
}

// safeLast4 returns the last 4 characters of a card number if it is at
// least 4 characters long. Returns empty string otherwise.
func safeLast4(number string) string {
	if len(number) < 4 {
		return ""
	}
	return number[len(number)-4:]
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
