package omnibox

import (
	"testing"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/stretchr/testify/require"
)

func TestValidateItem_NameRequired(t *testing.T) {
	err := ValidateItem(EditableItem{Name: ""})
	require.Error(t, err)
	require.Contains(t, err.Error(), "name is required")
}

func TestValidateItem_NamePresent(t *testing.T) {
	err := ValidateItem(EditableItem{Name: "My Login"})
	require.NoError(t, err)
}

func TestValidateItem_LoginAllowsDerivedNameFromURIAndUsername(t *testing.T) {
	err := ValidateItem(EditableItem{Type: vault.ItemTypeLogin, URI: "https://github.com/login", Username: "octocat"})
	require.NoError(t, err)
}

func TestValidateItem_LoginRequiresDerivableName(t *testing.T) {
	err := ValidateItem(EditableItem{Type: vault.ItemTypeLogin})
	require.Error(t, err)
	require.Contains(t, err.Error(), "site or username is required")
}

func TestDeriveLoginName(t *testing.T) {
	require.Equal(t, "github.com (octocat)", DeriveLoginName("https://github.com/login", "octocat"))
	require.Equal(t, "github.com", DeriveLoginName("github.com", ""))
	require.Equal(t, "octocat", DeriveLoginName("", "octocat"))
	require.Equal(t, "example.com", DeriveLoginName("https://user:pass@example.com/login", ""))
	require.Equal(t, "localhost:3000", DeriveLoginName("http://localhost:3000", ""))
	require.Equal(t, "user@example.com", DeriveLoginName("user@example.com", ""))
}

func TestEditableItemBuildItem_DerivesLoginName(t *testing.T) {
	e := EditableItem{Type: vault.ItemTypeLogin, URI: " https://github.com/login ", Username: " octocat ", Password: "secret"}
	item := e.BuildItem()
	require.Equal(t, "github.com (octocat)", item.Name)
	require.Equal(t, vault.ItemTypeLogin, item.Type)
	require.NotNil(t, item.Login)
	require.Equal(t, "octocat", item.Login.Username)
	require.Equal(t, "secret", item.Login.Password)
	require.Len(t, item.Login.URIs, 1)
	require.Equal(t, "https://github.com/login", item.Login.URIs[0].URI)
}

func TestEditableFromItem_RoundTrip_Login(t *testing.T) {
	item := vault.Item{
		Name:  "Example",
		Type:  vault.ItemTypeLogin,
		Notes: "some notes",
		Login: &vault.Login{
			Username: "user@example.com",
			Password: "s3cret!",
			TOTP:     "totp-secret",
			URIs:     []vault.URI{{URI: "https://example.com"}},
		},
	}
	e := EditableFromItem(item)
	require.Equal(t, "Example", e.Name)
	require.Equal(t, vault.ItemTypeLogin, e.Type)
	require.Equal(t, "user@example.com", e.Username)
	require.Equal(t, "s3cret!", e.Password)
	require.Equal(t, "totp-secret", e.TOTP)
	require.Equal(t, "https://example.com", e.URI)
	require.Equal(t, "some notes", e.Notes)

	built := e.BuildItem()
	require.Equal(t, item.Name, built.Name)
	require.Equal(t, item.Type, built.Type)
	require.NotNil(t, built.Login)
	require.Equal(t, item.Login.Username, built.Login.Username)
	require.Equal(t, item.Login.Password, built.Login.Password)
	require.Equal(t, item.Login.TOTP, built.Login.TOTP)
	require.Len(t, built.Login.URIs, 1)
	require.Equal(t, item.Login.URIs[0].URI, built.Login.URIs[0].URI)
	require.Equal(t, item.Notes, built.Notes)
}

func TestEditableFromItem_RoundTrip_SecureNote(t *testing.T) {
	item := vault.Item{
		Name:  "My Note",
		Type:  vault.ItemTypeSecureNote,
		Notes: "Secret content here",
	}
	e := EditableFromItem(item)
	require.Equal(t, "My Note", e.Name)
	require.Equal(t, vault.ItemTypeSecureNote, e.Type)
	require.Equal(t, "Secret content here", e.Notes)

	built := e.BuildItem()
	require.Equal(t, item.Name, built.Name)
	require.Equal(t, item.Type, built.Type)
	require.NotNil(t, built.SecureNote)
	require.Equal(t, item.Notes, built.SecureNote.Text)
}

func TestEditableFromItem_RoundTrip_SecureNote_TextInSecureNote(t *testing.T) {
	// Some secure notes store content in SecureNote.Text rather than the top-level Notes field.
	item := vault.Item{
		Name:       "My Note",
		Type:       vault.ItemTypeSecureNote,
		SecureNote: &vault.SecureNote{Text: "Secret body in SecureNote.Text"},
	}
	e := EditableFromItem(item)
	require.Equal(t, "My Note", e.Name)
	require.Equal(t, vault.ItemTypeSecureNote, e.Type)
	require.Equal(t, "Secret body in SecureNote.Text", e.Notes, "should capture SecureNote.Text")

	built := e.BuildItem()
	require.Equal(t, item.Name, built.Name)
	require.Equal(t, item.Type, built.Type)
	require.NotNil(t, built.SecureNote)
	require.Equal(t, "Secret body in SecureNote.Text", built.SecureNote.Text)
}

func TestEditableFromItem_RoundTrip_Card(t *testing.T) {
	item := vault.Item{
		Name: "My Card",
		Type: vault.ItemTypeCard,
		Card: &vault.Card{
			CardholderName: "Alice",
			Brand:          "Visa",
			Number:         "4111111111111111",
			ExpMonth:       "12",
			ExpYear:        "2028",
			Code:           "123",
		},
	}
	e := EditableFromItem(item)
	require.Equal(t, "My Card", e.Name)
	require.Equal(t, vault.ItemTypeCard, e.Type)
	require.Equal(t, "Alice", e.CardholderName)
	require.Equal(t, "Visa", e.CardBrand)
	require.Equal(t, "4111111111111111", e.CardNumber)
	require.Equal(t, "12", e.CardExpMonth)
	require.Equal(t, "2028", e.CardExpYear)
	require.Equal(t, "123", e.CardCode)

	built := e.BuildItem()
	require.Equal(t, item.Name, built.Name)
	require.Equal(t, item.Type, built.Type)
	require.NotNil(t, built.Card)
	require.Equal(t, item.Card.CardholderName, built.Card.CardholderName)
	require.Equal(t, item.Card.Brand, built.Card.Brand)
	require.Equal(t, item.Card.Number, built.Card.Number)
	require.Equal(t, item.Card.ExpMonth, built.Card.ExpMonth)
	require.Equal(t, item.Card.ExpYear, built.Card.ExpYear)
	require.Equal(t, item.Card.Code, built.Card.Code)
}

func TestEditableFromItem_RoundTrip_Identity(t *testing.T) {
	item := vault.Item{
		Name: "My Identity",
		Type: vault.ItemTypeIdentity,
		Identity: &vault.Identity{
			FirstName:      "Alice",
			LastName:       "Smith",
			Email:          "alice@example.com",
			Phone:          "+1-555-1234",
			Username:       "alice_s",
			SSN:            "999-99-9999",
			PassportNumber: "P123456",
			LicenseNumber:  "D789012",
		},
	}
	e := EditableFromItem(item)
	require.Equal(t, "My Identity", e.Name)
	require.Equal(t, vault.ItemTypeIdentity, e.Type)
	require.Equal(t, "Alice", e.IdentityFirstName)
	require.Equal(t, "Smith", e.IdentityLastName)
	require.Equal(t, "alice@example.com", e.IdentityEmail)
	require.Equal(t, "+1-555-1234", e.IdentityPhone)
	require.Equal(t, "alice_s", e.IdentityUsername)
	require.Equal(t, "999-99-9999", e.IdentitySSN)
	require.Equal(t, "P123456", e.IdentityPassportNumber)
	require.Equal(t, "D789012", e.IdentityLicenseNumber)

	built := e.BuildItem()
	require.Equal(t, item.Name, built.Name)
	require.Equal(t, item.Type, built.Type)
	require.NotNil(t, built.Identity)
	require.Equal(t, item.Identity.FirstName, built.Identity.FirstName)
	require.Equal(t, item.Identity.LastName, built.Identity.LastName)
	require.Equal(t, item.Identity.Email, built.Identity.Email)
	require.Equal(t, item.Identity.Phone, built.Identity.Phone)
	require.Equal(t, item.Identity.Username, built.Identity.Username)
	require.Equal(t, item.Identity.SSN, built.Identity.SSN)
	require.Equal(t, item.Identity.PassportNumber, built.Identity.PassportNumber)
	require.Equal(t, item.Identity.LicenseNumber, built.Identity.LicenseNumber)
}

func TestBuildItem_Login(t *testing.T) {
	e := EditableItem{
		Name:     "Test Login",
		Type:     vault.ItemTypeLogin,
		Username: "user@example.com",
		URI:      "https://example.com",
	}
	item := e.BuildItem()
	require.Equal(t, "Test Login", item.Name)
	require.Equal(t, vault.ItemTypeLogin, item.Type)
	require.NotNil(t, item.Login)
	require.Equal(t, "user@example.com", item.Login.Username)
	require.Len(t, item.Login.URIs, 1)
	require.Equal(t, "https://example.com", item.Login.URIs[0].URI)
	// Password should be empty (not set in EditableItem)
	require.Empty(t, item.Login.Password)
}

func TestBuildItem_SecureNote(t *testing.T) {
	e := EditableItem{
		Name:  "My Note",
		Type:  vault.ItemTypeSecureNote,
		Notes: "Secret content",
	}
	item := e.BuildItem()
	require.Equal(t, "My Note", item.Name)
	require.Equal(t, vault.ItemTypeSecureNote, item.Type)
	require.NotNil(t, item.SecureNote)
	require.Equal(t, "Secret content", item.SecureNote.Text)
}

func TestBuildItem_Card(t *testing.T) {
	e := EditableItem{
		Name:           "My Card",
		Type:           vault.ItemTypeCard,
		CardholderName: "Alice",
		CardBrand:      "Visa",
	}
	item := e.BuildItem()
	require.Equal(t, "My Card", item.Name)
	require.Equal(t, vault.ItemTypeCard, item.Type)
	require.NotNil(t, item.Card)
	require.Equal(t, "Alice", item.Card.CardholderName)
	require.Equal(t, "Visa", item.Card.Brand)
	// Card secrets not set in this EditableItem
	require.Empty(t, item.Card.Number)
	require.Empty(t, item.Card.Code)
}

func TestBuildItem_Identity(t *testing.T) {
	e := EditableItem{
		Name:              "My Identity",
		Type:              vault.ItemTypeIdentity,
		IdentityFirstName: "Alice",
		IdentityLastName:  "Smith",
		IdentityEmail:     "alice@example.com",
	}
	item := e.BuildItem()
	require.Equal(t, "My Identity", item.Name)
	require.Equal(t, vault.ItemTypeIdentity, item.Type)
	require.NotNil(t, item.Identity)
	require.Equal(t, "Alice", item.Identity.FirstName)
	require.Equal(t, "Smith", item.Identity.LastName)
	require.Equal(t, "alice@example.com", item.Identity.Email)
	// Identity secrets not set in this EditableItem
	require.Empty(t, item.Identity.SSN)
	require.Empty(t, item.Identity.PassportNumber)
	require.Empty(t, item.Identity.LicenseNumber)
}
