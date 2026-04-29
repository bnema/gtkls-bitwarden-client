package omnibox

import (
	"strings"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
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
			d.PasswordPresent = item.Login.Password != ""
			d.TOTPPresent = item.Login.TOTP != ""
		}

	case vault.ItemTypeCard:
		if item.Card != nil {
			d.CardBrand = item.Card.Brand
			d.CardLast4 = safeLast4(item.Card.Number)
			// CodePresent is implied by presence but not exposed as a field.
			// Last4 only, never full number or code.
		}

	case vault.ItemTypeIdentity:
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
			d.IdentityName = strings.Join(parts, " ")
			// SSN, PassportNumber, LicenseNumber are intentionally NOT exposed.
		}
	}

	// Attachment file names only (no URLs/content).
	for _, a := range item.Attachments {
		d.Attachments = append(d.Attachments, a.FileName)
	}

	return d
}
