// Package display provides shared UI display helpers for vault items.
// All helpers are safe to use across GUI adapter packages and never expose
// sensitive secret values (passwords, TOTP, card codes, SSN, etc.).
package display

import (
	"net/url"
	"strings"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// BuildRowSubtitle builds a safe one-line subtitle for a vault item row.
// Sensitive data (passwords, TOTP, card codes, SSN, passport, license) is
// never included in the result.
func BuildRowSubtitle(item vault.Item) string {
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
			parts = append(parts, SafeURI(item.Login.URIs[0].URI))
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
		if last4 := SafeLast4(item.Card.Number); last4 != "" {
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

// SafeURI attempts to extract just the host from a URI string.
// If parsing fails, the raw URI is returned with query/fragment stripped.
func SafeURI(raw string) string {
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

// SafeLast4 returns the last 4 runes of a string if it is at least 4 runes
// long. Operates on runes to handle multi-byte characters correctly.
// Returns empty string otherwise.
func SafeLast4(s string) string {
	runes := []rune(s)
	if len(runes) < 4 {
		return ""
	}
	return string(runes[len(runes)-4:])
}

// BuildIdentityName returns the full display name for an Identity vault item.
// Combines Title, FirstName, MiddleName, and LastName separated by spaces.
// Returns empty string if none are set.
func BuildIdentityName(identity *vault.Identity) string {
	if identity == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	if identity.Title != "" {
		parts = append(parts, identity.Title)
	}
	if identity.FirstName != "" {
		parts = append(parts, identity.FirstName)
	}
	if identity.MiddleName != "" {
		parts = append(parts, identity.MiddleName)
	}
	if identity.LastName != "" {
		parts = append(parts, identity.LastName)
	}
	return strings.Join(parts, " ")
}
