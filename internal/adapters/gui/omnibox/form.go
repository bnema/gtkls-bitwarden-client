package omnibox

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// EditableItem holds all the fields a user can edit for a vault item.
// Secret values (password, TOTP, card number, card code, SSN, passport, license)
// are included here in the form model only and must never be logged or printed.
type EditableItem struct {
	Name     string
	Type     vault.ItemType
	Username string
	URI      string
	Password string
	TOTP     string
	Notes    string

	// Card fields
	CardholderName string
	CardBrand      string
	CardNumber     string
	CardExpMonth   string
	CardExpYear    string
	CardCode       string

	// Identity fields
	IdentityFirstName      string
	IdentityLastName       string
	IdentityEmail          string
	IdentityPhone          string
	IdentityUsername       string
	IdentitySSN            string
	IdentityPassportNumber string
	IdentityLicenseNumber  string
}

// EditableFromItem creates an EditableItem from a vault.Item, preserving
// current values including secrets.
func EditableFromItem(item vault.Item) EditableItem {
	e := EditableItem{
		Name:  item.Name,
		Type:  item.Type,
		Notes: item.Notes,
	}
	switch item.Type {
	case vault.ItemTypeLogin:
		if item.Login != nil {
			e.Username = item.Login.Username
			e.Password = item.Login.Password
			e.TOTP = item.Login.TOTP
			if len(item.Login.URIs) > 0 {
				e.URI = item.Login.URIs[0].URI
			}
		}
	case vault.ItemTypeSecureNote:
		if item.SecureNote != nil && item.SecureNote.Text != "" {
			e.Notes = item.SecureNote.Text
		}
	case vault.ItemTypeCard:
		if item.Card != nil {
			e.CardholderName = item.Card.CardholderName
			e.CardBrand = item.Card.Brand
			e.CardNumber = item.Card.Number
			e.CardExpMonth = item.Card.ExpMonth
			e.CardExpYear = item.Card.ExpYear
			e.CardCode = item.Card.Code
		}
	case vault.ItemTypeIdentity:
		if item.Identity != nil {
			e.IdentityFirstName = item.Identity.FirstName
			e.IdentityLastName = item.Identity.LastName
			e.IdentityEmail = item.Identity.Email
			e.IdentityPhone = item.Identity.Phone
			e.IdentityUsername = item.Identity.Username
			e.IdentitySSN = item.Identity.SSN
			e.IdentityPassportNumber = item.Identity.PassportNumber
			e.IdentityLicenseNumber = item.Identity.LicenseNumber
		}
	}
	return e
}

// BuildItem creates a vault.Item from the EditableItem fields.
func (e EditableItem) BuildItem() vault.Item {
	name := strings.TrimSpace(e.Name)
	if e.Type == vault.ItemTypeLogin && name == "" {
		name = DeriveLoginName(e.URI, e.Username)
	}

	item := vault.Item{
		Name:  name,
		Type:  e.Type,
		Notes: e.Notes,
	}
	switch e.Type {
	case vault.ItemTypeLogin:
		login := &vault.Login{
			Username: strings.TrimSpace(e.Username),
			// Password whitespace is intentional secret material; do not trim it.
			Password: e.Password,
			TOTP:     strings.TrimSpace(e.TOTP),
		}
		if uri := strings.TrimSpace(e.URI); uri != "" {
			login.URIs = []vault.URI{{URI: uri}}
		}
		item.Login = login
	case vault.ItemTypeSecureNote:
		item.SecureNote = &vault.SecureNote{Text: e.Notes}
	case vault.ItemTypeCard:
		item.Card = &vault.Card{
			CardholderName: e.CardholderName,
			Brand:          e.CardBrand,
			Number:         e.CardNumber,
			ExpMonth:       e.CardExpMonth,
			ExpYear:        e.CardExpYear,
			Code:           e.CardCode,
		}
	case vault.ItemTypeIdentity:
		item.Identity = &vault.Identity{
			FirstName:      e.IdentityFirstName,
			LastName:       e.IdentityLastName,
			Email:          e.IdentityEmail,
			Phone:          e.IdentityPhone,
			Username:       e.IdentityUsername,
			SSN:            e.IdentitySSN,
			PassportNumber: e.IdentityPassportNumber,
			LicenseNumber:  e.IdentityLicenseNumber,
		}
	}
	return item
}

// ValidateItem checks that the EditableItem has a non-empty Name.
// Returns nil if valid, or an error describing the first issue.
func ValidateItem(e EditableItem) error {
	if e.Type == vault.ItemTypeLogin {
		if strings.TrimSpace(e.Name) == "" && DeriveLoginName(e.URI, e.Username) == "" {
			return errors.New("site or username is required")
		}
		return nil
	}

	if strings.TrimSpace(e.Name) == "" {
		return errors.New("item name is required")
	}
	return nil
}

// DeriveLoginName creates a concise display name from a login URI/site and
// username. The user can type only a site plus optional username, without
// manually filling a separate name field.
func DeriveLoginName(site, username string) string {
	domain := ExtractDomain(strings.TrimSpace(site))
	username = strings.TrimSpace(username)
	if domain == "" {
		return username
	}
	if username != "" {
		return fmt.Sprintf("%s (%s)", domain, username)
	}
	return domain
}

// ExtractDomain parses a URL or bare hostname and returns the host portion.
func ExtractDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "//") && strings.Contains(raw, "@") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := hostWithOptionalPort(u)
	if host == "" && u.User != nil && !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	if host == "" {
		u2, _ := url.Parse("https://" + raw)
		if u2 != nil {
			host = hostWithOptionalPort(u2)
		}
	}
	if host == "" {
		return raw
	}
	return host
}

func hostWithOptionalPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	if port := u.Port(); port != "" {
		return host + ":" + port
	}
	return host
}
