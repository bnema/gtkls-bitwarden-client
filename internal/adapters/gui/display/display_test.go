package display

import (
	"testing"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/stretchr/testify/require"
)

func TestBuildRowSubtitle_Login(t *testing.T) {
	item := vault.Item{
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			Username: "user@example.com",
			Password: "supersecret",
			TOTP:     "JBSWY3DPEHPK3PXP",
			URIs:     []vault.URI{{URI: "https://example.com/login"}},
		},
	}
	sub := BuildRowSubtitle(item)
	require.Contains(t, sub, "user@example.com")
	require.Contains(t, sub, "example.com")
	require.NotContains(t, sub, "supersecret")
	require.NotContains(t, sub, "JBSWY3DPEHPK3PXP")
}

func TestBuildRowSubtitle_Login_NilLogin(t *testing.T) {
	item := vault.Item{Type: vault.ItemTypeLogin}
	require.Empty(t, BuildRowSubtitle(item))
}

func TestBuildRowSubtitle_Login_WithHostParsing(t *testing.T) {
	item := vault.Item{
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			Username: "octocat",
			URIs:     []vault.URI{{URI: "https://github.com/login?redirect=home#section"}},
		},
	}
	sub := BuildRowSubtitle(item)
	require.Contains(t, sub, "octocat")
	require.Contains(t, sub, "github.com")
	require.NotContains(t, sub, "?redirect=home")
	require.NotContains(t, sub, "#section")
}

func TestBuildRowSubtitle_Login_FallbackRawURI(t *testing.T) {
	item := vault.Item{
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			URIs: []vault.URI{{URI: "http://192.168.1.1:8080/admin?q=test"}},
		},
	}
	sub := BuildRowSubtitle(item)
	require.Contains(t, sub, "192.168.1.1:8080")
}

func TestBuildRowSubtitle_SecureNote(t *testing.T) {
	item := vault.Item{
		Type:       vault.ItemTypeSecureNote,
		SecureNote: &vault.SecureNote{Text: "secret body"},
	}
	require.Equal(t, "Secure note", BuildRowSubtitle(item))
}

func TestBuildRowSubtitle_Card(t *testing.T) {
	item := vault.Item{
		Type: vault.ItemTypeCard,
		Card: &vault.Card{
			Brand:  "Visa",
			Number: "4111111111111111",
			Code:   "123",
		},
	}
	sub := BuildRowSubtitle(item)
	require.Contains(t, sub, "Visa")
	require.Contains(t, sub, "•••• 1111")
	require.NotContains(t, sub, "4111111111111111")
	require.NotContains(t, sub, "123")
}

func TestBuildRowSubtitle_Card_ShortNumber(t *testing.T) {
	item := vault.Item{
		Type: vault.ItemTypeCard,
		Card: &vault.Card{
			Brand:  "Amex",
			Number: "123",
		},
	}
	sub := BuildRowSubtitle(item)
	require.Contains(t, sub, "Amex")
	require.NotContains(t, sub, "••••")
}

func TestBuildRowSubtitle_Card_NilCard(t *testing.T) {
	item := vault.Item{Type: vault.ItemTypeCard}
	require.Empty(t, BuildRowSubtitle(item))
}

func TestBuildRowSubtitle_Identity(t *testing.T) {
	item := vault.Item{
		Type: vault.ItemTypeIdentity,
		Identity: &vault.Identity{
			FirstName:      "Alice",
			LastName:       "Smith",
			Email:          "alice@example.com",
			Username:       "alice123",
			SSN:            "999-99-9999",
			PassportNumber: "P123456789",
			LicenseNumber:  "D1234567",
		},
	}
	sub := BuildRowSubtitle(item)
	require.Contains(t, sub, "Alice")
	require.Contains(t, sub, "Smith")
	require.Contains(t, sub, "alice@example.com")
	require.Contains(t, sub, "alice123")
	require.NotContains(t, sub, "999-99-9999")
	require.NotContains(t, sub, "P123456789")
	require.NotContains(t, sub, "D1234567")
}

func TestBuildRowSubtitle_Identity_NilIdentity(t *testing.T) {
	item := vault.Item{Type: vault.ItemTypeIdentity}
	require.Empty(t, BuildRowSubtitle(item))
}

func TestBuildRowSubtitle_UnknownType(t *testing.T) {
	item := vault.Item{Type: "unknown"}
	require.Empty(t, BuildRowSubtitle(item))
}

func TestSafeURI_Standard(t *testing.T) {
	require.Equal(t, "example.com", SafeURI("https://example.com/path?q=1#frag"))
}

func TestSafeURI_IPPort(t *testing.T) {
	require.Equal(t, "192.168.1.1:8080", SafeURI("http://192.168.1.1:8080/admin"))
}

func TestSafeURI_NoHost(t *testing.T) {
	require.Equal(t, "/path", SafeURI("/path?q=1"))
}

func TestSafeURI_Invalid(t *testing.T) {
	require.Equal(t, "not-a-url", SafeURI("not-a-url"))
}

func TestSafeURI_Empty(t *testing.T) {
	require.Empty(t, SafeURI(""))
}

func TestSafeLast4_Normal(t *testing.T) {
	require.Equal(t, "1111", SafeLast4("4111111111111111"))
}

func TestSafeLast4_Short(t *testing.T) {
	require.Empty(t, SafeLast4("123"))
}

func TestSafeLast4_Exactly4(t *testing.T) {
	require.Equal(t, "abcd", SafeLast4("abcd"))
}

func TestSafeLast4_Empty(t *testing.T) {
	require.Empty(t, SafeLast4(""))
}

func TestSafeLast4_Unicode(t *testing.T) {
	// Multi-byte characters: each emoji is 4 bytes, 1 rune.
	// "abc😀😎" = 5 runes, last 4 = "bc😀😎"
	require.Equal(t, "bc😀😎", SafeLast4("abc😀😎"))
}

func TestSafeLast4_UnicodeShort(t *testing.T) {
	require.Empty(t, SafeLast4("a😀"))
}
