package omnibox

import (
	"testing"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/stretchr/testify/require"
)

func TestPrimaryActionFor_DefaultCopyPassword(t *testing.T) {
	row := Row{ID: "1", Title: "Test"}
	cfg := config.Default() // default primary action is copy_password

	action := PrimaryActionFor(row, cfg)
	require.Equal(t, ActionCopyPassword, action)
}

func TestPrimaryActionFor_CopyUsername(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.DefaultPrimaryAction = config.ActionCopyUsername

	action := PrimaryActionFor(Row{}, cfg)
	require.Equal(t, ActionCopyUsername, action)
}

func TestPrimaryActionFor_OpenDetail(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.DefaultPrimaryAction = config.ActionOpenDetail

	action := PrimaryActionFor(Row{}, cfg)
	require.Equal(t, ActionOpenDetail, action)
}

func TestPrimaryActionFor_NilConfig(t *testing.T) {
	action := PrimaryActionFor(Row{}, nil)
	require.Equal(t, ActionCopyPassword, action)
}

func TestPrimaryActionFor_OpenURLFallback(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.DefaultPrimaryAction = config.ActionOpenURL

	action := PrimaryActionFor(Row{}, cfg)
	require.Equal(t, ActionCopyPassword, action, "open_url should fall back to copy_password")
}

func TestRowsFromItems_Nil(t *testing.T) {
	rows := RowsFromItems(nil)
	require.Nil(t, rows)
}

func TestRowsFromScored_Nil(t *testing.T) {
	rows := RowsFromScored(nil)
	require.Nil(t, rows)
}

func TestRowsFromItems_Login_ExcludesSecrets(t *testing.T) {
	items := []vault.Item{
		{
			ID:   "login-1",
			Name: "My Login",
			Type: vault.ItemTypeLogin,
			Login: &vault.Login{
				Username: "user@example.com",
				Password: "supersecret",
				TOTP:     "JBSWY3DPEHPK3PXP",
				URIs:     []vault.URI{{URI: "https://example.com/login"}},
			},
		},
	}

	rows := RowsFromItems(items)
	require.Len(t, rows, 1)
	require.Equal(t, "My Login", rows[0].Title)
	require.Contains(t, rows[0].Subtitle, "user@example.com")
	require.Contains(t, rows[0].Subtitle, "example.com")
	require.NotContains(t, rows[0].Subtitle, "supersecret")
	require.NotContains(t, rows[0].Subtitle, "JBSWY3DPEHPK3PXP")
}

func TestRowsFromItems_SecureNote_ExcludesBody(t *testing.T) {
	items := []vault.Item{
		{
			ID:   "note-1",
			Name: "My Secret Note",
			Type: vault.ItemTypeSecureNote,
			SecureNote: &vault.SecureNote{
				Text: "This is the secret body that must never appear in subtitle",
			},
		},
	}

	rows := RowsFromItems(items)
	require.Equal(t, "Secure note", rows[0].Subtitle)
	require.NotContains(t, rows[0].Subtitle, "secret body")
}

func TestRowsFromItems_Card_ExcludesFullNumberAndCode(t *testing.T) {
	items := []vault.Item{
		{
			ID:   "card-1",
			Name: "My Visa",
			Type: vault.ItemTypeCard,
			Card: &vault.Card{
				Brand:  "Visa",
				Number: "4111111111111111",
				Code:   "123",
			},
		},
	}

	rows := RowsFromItems(items)
	require.Contains(t, rows[0].Subtitle, "Visa")
	require.Contains(t, rows[0].Subtitle, "•••• 1111")
	require.NotContains(t, rows[0].Subtitle, "4111111111111111")
	require.NotContains(t, rows[0].Subtitle, "123")
}

func TestRowsFromItems_Identity_ExcludesSSNPassportLicense(t *testing.T) {
	items := []vault.Item{
		{
			ID:   "identity-1",
			Name: "Alice Identity",
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
		},
	}

	rows := RowsFromItems(items)
	require.Contains(t, rows[0].Subtitle, "Alice")
	require.Contains(t, rows[0].Subtitle, "Smith")
	require.Contains(t, rows[0].Subtitle, "alice@example.com")
	require.Contains(t, rows[0].Subtitle, "alice123")
	require.NotContains(t, rows[0].Subtitle, "999-99-9999")
	require.NotContains(t, rows[0].Subtitle, "P123456789")
	require.NotContains(t, rows[0].Subtitle, "D1234567")
}

func TestRowsFromItems_HiddenCustomFieldsExcluded(t *testing.T) {
	items := []vault.Item{
		{
			ID:   "field-1",
			Name: "Item with fields",
			Type: vault.ItemTypeLogin,
			Login: &vault.Login{
				Username: "test",
				URIs:     []vault.URI{{URI: "https://example.com"}},
			},
			Fields: []vault.Field{
				{Name: "visible", Value: "visible-value", Hidden: false},
				{Name: "hidden", Value: "hidden-value", Hidden: true},
			},
		},
	}

	rows := RowsFromItems(items)
	require.NotContains(t, rows[0].Subtitle, "hidden-value")
}

func TestRowsFromItems_Badge(t *testing.T) {
	items := []vault.Item{
		{
			ID:         "badge-1",
			Name:       "Badge Test",
			Type:       vault.ItemTypeLogin,
			Favorite:   true,
			Deleted:    true,
			SyncStatus: vault.SyncStatusPending,
			Login:      &vault.Login{Username: "test"},
		},
	}

	rows := RowsFromItems(items)
	require.Contains(t, rows[0].Badge, "Deleted")
	require.Contains(t, rows[0].Badge, "Pending")
	require.Contains(t, rows[0].Badge, "★")
}
