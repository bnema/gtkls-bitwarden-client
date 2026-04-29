package omnibox

import (
	"testing"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
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
	// Password should be empty
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
		Name: "My Card",
		Type: vault.ItemTypeCard,
	}
	item := e.BuildItem()
	require.Equal(t, "My Card", item.Name)
	require.Equal(t, vault.ItemTypeCard, item.Type)
	require.NotNil(t, item.Card)
	// No card secrets exposed
	require.Empty(t, item.Card.Number)
	require.Empty(t, item.Card.Code)
}

func TestBuildItem_Identity(t *testing.T) {
	e := EditableItem{
		Name: "My Identity",
		Type: vault.ItemTypeIdentity,
	}
	item := e.BuildItem()
	require.Equal(t, "My Identity", item.Name)
	require.Equal(t, vault.ItemTypeIdentity, item.Type)
	require.NotNil(t, item.Identity)
	// No identity secrets exposed
	require.Empty(t, item.Identity.SSN)
	require.Empty(t, item.Identity.PassportNumber)
	require.Empty(t, item.Identity.LicenseNumber)
}
