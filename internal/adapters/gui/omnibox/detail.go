package omnibox

import (
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/display"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// Detail represents a vault item detail with safe display fields.
// Sensitive values are never included; presence is indicated by booleans.
type Detail struct {
	ID       string
	Title    string
	Type     string
	Username string
	URI      string

	NotesPresent    bool
	PasswordPresent bool
	TOTPPresent     bool
	Attachments     []string
	Conflict        bool
	Pending         bool
	Deleted         bool

	// Login safe fields
	URIs []string

	// Card safe fields
	CardBrand string
	CardLast4 string

	// Identity safe fields
	IdentityName string
}

// DetailFromItem converts a vault Item to a safe Detail.
func DetailFromItem(item vault.Item) Detail {
	d := Detail{
		ID:           item.ID,
		Title:        item.Name,
		Type:         string(item.Type),
		Conflict:     item.SyncStatus == vault.SyncStatusConflict,
		Pending:      item.SyncStatus == vault.SyncStatusPending,
		Deleted:      item.Deleted,
		NotesPresent: item.Notes != "",
	}

	switch item.Type {
	case vault.ItemTypeLogin:
		if item.Login != nil {
			d.Username = item.Login.Username
			if len(item.Login.URIs) > 0 {
				d.URI = item.Login.URIs[0].URI
			}
			for _, u := range item.Login.URIs {
				d.URIs = append(d.URIs, u.URI)
			}
			d.PasswordPresent = item.Login.Password != ""
			d.TOTPPresent = item.Login.TOTP != ""
		}

	case vault.ItemTypeCard:
		if item.Card != nil {
			d.CardBrand = item.Card.Brand
			d.CardLast4 = display.SafeLast4(item.Card.Number)
			// CodePresent is implied by presence but not exposed as a field.
			// Last4 only, never full number or code.
		}

	case vault.ItemTypeIdentity:
		if item.Identity != nil {
			d.IdentityName = display.BuildIdentityName(item.Identity)
			// SSN, PassportNumber, LicenseNumber are intentionally NOT exposed.
		}
	}

	// Attachment file names only (no URLs/content).
	for _, a := range item.Attachments {
		d.Attachments = append(d.Attachments, a.FileName)
	}

	return d
}
