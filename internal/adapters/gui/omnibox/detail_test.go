package omnibox

import (
	"testing"

	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/stretchr/testify/require"
)

func TestDetailFromItem_Login(t *testing.T) {
	item := vault.Item{
		ID:   "det-login-1",
		Name: "My Login",
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			Username: "user@example.com",
			Password: "secret",
			TOTP:     "totp-secret",
			URIs:     []vault.URI{{URI: "https://example.com"}},
		},
	}

	d := DetailFromItem(item)
	require.Equal(t, "user@example.com", d.Username)
	require.Equal(t, "https://example.com", d.URI)
	require.True(t, d.PasswordPresent)
	require.True(t, d.TOTPPresent)
	// Detail intentionally has no Password or TOTP string fields — only
	// boolean presence indicators (PasswordPresent, TOTPPresent).
	// This test verifies the secret values are not leaked via any field.
}

func TestDetailFromItem_Login_NilLogin(t *testing.T) {
	item := vault.Item{
		ID:   "det-login-2",
		Name: "Empty Login",
		Type: vault.ItemTypeLogin,
	}

	d := DetailFromItem(item)
	require.Empty(t, d.Username)
	require.Empty(t, d.URI)
	require.False(t, d.PasswordPresent)
	require.False(t, d.TOTPPresent)
}

func TestDetailFromItem_Card_ExcludesFullNumberAndCode(t *testing.T) {
	item := vault.Item{
		ID:   "det-card-1",
		Name: "My Card",
		Type: vault.ItemTypeCard,
		Card: &vault.Card{
			CardholderName: "Alice",
			Brand:          "Visa",
			Number:         "4111111111111111",
			Code:           "123",
			ExpMonth:       "12",
			ExpYear:        "2028",
		},
	}

	d := DetailFromItem(item)
	require.Equal(t, "Visa", d.CardBrand)
	require.Equal(t, "1111", d.CardLast4)
	// Full number and code never exposed
	require.NotEqual(t, "4111111111111111", d.CardLast4)
}

func TestDetailFromItem_Identity_ExcludesSSNPassportLicense(t *testing.T) {
	item := vault.Item{
		ID:   "det-identity-1",
		Name: "Alice Identity",
		Type: vault.ItemTypeIdentity,
		Identity: &vault.Identity{
			Title:          "Dr.",
			FirstName:      "Alice",
			MiddleName:     "M",
			LastName:       "Smith",
			Email:          "alice@example.com",
			SSN:            "999-99-9999",
			PassportNumber: "P123",
			LicenseNumber:  "D456",
		},
	}

	d := DetailFromItem(item)
	require.Contains(t, d.IdentityName, "Dr.")
	require.Contains(t, d.IdentityName, "Alice")
	require.Contains(t, d.IdentityName, "Smith")
	// Sensitive government IDs not exposed
	require.NotContains(t, d.IdentityName, "999-99-9999")
	require.NotContains(t, d.IdentityName, "P123")
	require.NotContains(t, d.IdentityName, "D456")
}

func TestDetailFromItem_SecureNote_NotesPresent(t *testing.T) {
	item := vault.Item{
		ID:    "det-note-1",
		Name:  "My Note",
		Type:  vault.ItemTypeSecureNote,
		Notes: "This is a secure note body",
	}

	d := DetailFromItem(item)
	require.True(t, d.NotesPresent)
}

func TestDetailFromItem_Attachments(t *testing.T) {
	item := vault.Item{
		ID:   "det-attach-1",
		Name: "With Attachments",
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			Username: "test",
		},
		Attachments: []vault.Attachment{
			{ID: "a1", FileName: "photo.jpg", Size: 1024, URL: "https://example.com/photo"},
			{ID: "a2", FileName: "doc.pdf", Size: 2048, URL: "https://example.com/doc"},
		},
	}

	d := DetailFromItem(item)
	require.Len(t, d.Attachments, 2)
	require.Equal(t, "photo.jpg", d.Attachments[0])
	require.Equal(t, "doc.pdf", d.Attachments[1])
}

func TestDetailFromItem_ConflictPendingDeleted(t *testing.T) {
	item := vault.Item{
		ID:         "det-cpd-1",
		Name:       "State Test",
		Type:       vault.ItemTypeLogin,
		Deleted:    true,
		SyncStatus: vault.SyncStatusConflict,
		ConflictID: "conflict-1",
		Login:      &vault.Login{Username: "test"},
	}

	d := DetailFromItem(item)
	require.True(t, d.Conflict)
	require.Equal(t, "conflict-1", d.ConflictID)
	require.True(t, d.Deleted)
	require.False(t, d.Pending)
}

func TestConflictResolutionActions_OnlyForConflictedItemsWithConflictID(t *testing.T) {
	require.Empty(t, ConflictResolutionActions(Detail{}))
	require.Empty(t, ConflictResolutionActions(Detail{Conflict: true}))

	actions := ConflictResolutionActions(Detail{Conflict: true, ConflictID: "conflict-1"})
	require.Len(t, actions, 3)
	require.Equal(t, "Keep local", actions[0].Label)
	require.Equal(t, coresync.ResolutionKeepLocal, actions[0].Resolution)
	require.Equal(t, "Use remote", actions[1].Label)
	require.Equal(t, coresync.ResolutionKeepRemote, actions[1].Resolution)
	require.Equal(t, "Duplicate local", actions[2].Label)
	require.Equal(t, coresync.ResolutionDuplicateLocal, actions[2].Resolution)
}
