package omnibox

import (
	"errors"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
)

// EditableItem holds the fields a user can edit for a vault item.
// Only non-secret, non-identifying fields are exposed.
type EditableItem struct {
	Name     string
	Type     vault.ItemType
	Username string
	URI      string
	Notes    string
}

// BuildItem creates a vault.Item from the EditableItem fields.
// Secrets (password, TOTP, card number, card code, SSN, passport, license)
// are not part of EditableItem and remain empty in the returned Item.
func (e EditableItem) BuildItem() vault.Item {
	item := vault.Item{
		Name:  e.Name,
		Type:  e.Type,
		Notes: e.Notes,
	}
	switch e.Type {
	case vault.ItemTypeLogin:
		item.Login = &vault.Login{
			Username: e.Username,
		}
		if e.URI != "" {
			item.Login.URIs = []vault.URI{{URI: e.URI}}
		}
	case vault.ItemTypeSecureNote:
		item.SecureNote = &vault.SecureNote{Text: e.Notes}
	case vault.ItemTypeCard:
		item.Card = &vault.Card{}
	case vault.ItemTypeIdentity:
		item.Identity = &vault.Identity{}
	}
	return item
}

// ValidateItem checks that the EditableItem has a non-empty Name.
// Returns nil if valid, or an error describing the first issue.
func ValidateItem(e EditableItem) error {
	if e.Name == "" {
		return errors.New("item name is required")
	}
	return nil
}
