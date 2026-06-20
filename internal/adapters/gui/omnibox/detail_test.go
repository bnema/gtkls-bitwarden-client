package omnibox

import (
	"strings"
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

func TestDetailFromConflictDetailShowsSafeLocalAndRemoteSummaries(t *testing.T) {
	local := vault.Item{
		ID:    "item-1",
		Name:  "Local Site",
		Type:  vault.ItemTypeLogin,
		Notes: "local private notes",
		Login: &vault.Login{
			Username: "local-user",
			Password: "local-password-secret",
			TOTP:     "local-totp-secret",
			URIs:     []vault.URI{{URI: "https://local.example/login?token=query-secret"}},
		},
		Fields: []vault.Field{
			{Name: "visible-field", Value: "visible-secret"},
			{Name: "hidden-field", Value: "hidden-secret", Hidden: true},
		},
	}
	remote := vault.Item{
		ID:   "item-1",
		Name: "Remote Site",
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			Username: "remote-user",
			Password: "remote-password-secret",
			TOTP:     "remote-totp-secret",
			URIs:     []vault.URI{{URI: "https://remote.example/sign-in?secret=value"}},
		},
	}

	d := DetailFromConflictDetail(coresync.ConflictDetail{
		Conflict:   coresync.Conflict{ID: "conflict-1", ItemID: "item-1", Reason: coresync.ConflictBothModified},
		LocalItem:  &local,
		RemoteItem: &remote,
	})

	require.True(t, d.Conflict)
	require.True(t, d.ConflictOnly)
	require.Equal(t, "conflict-1", d.ConflictID)
	require.Equal(t, "Local Site", d.Title)
	require.Empty(t, d.URI, "conflict detail must not render raw item URI before safe summaries")
	require.False(t, d.PasswordPresent, "conflict detail must not render secret presence outside safe summaries")
	require.False(t, d.TOTPPresent, "conflict detail must not render secret presence outside safe summaries")
	require.Len(t, d.ConflictSummaries, 2)

	localText := conflictSummaryText(d.ConflictSummaries[0])
	require.Contains(t, localText, "Name: Local Site")
	require.Contains(t, localText, "Username: local-user")
	require.Contains(t, localText, "URI: local.example")
	require.Contains(t, localText, "Password: stored (hidden)")
	require.Contains(t, localText, "TOTP: stored (hidden)")
	require.Contains(t, localText, "Notes: present (hidden)")
	require.Contains(t, localText, "Visible custom fields: visible-field")
	require.Contains(t, localText, "Hidden custom fields: 1")
	require.NotContains(t, localText, "local-password-secret")
	require.NotContains(t, localText, "local-totp-secret")
	require.NotContains(t, localText, "query-secret")
	require.NotContains(t, localText, "visible-secret")
	require.NotContains(t, localText, "hidden-secret")

	remoteText := conflictSummaryText(d.ConflictSummaries[1])
	require.Contains(t, remoteText, "Name: Remote Site")
	require.Contains(t, remoteText, "Username: remote-user")
	require.Contains(t, remoteText, "URI: remote.example")
	require.Contains(t, remoteText, "Password: stored (hidden)")
	require.Contains(t, remoteText, "TOTP: stored (hidden)")
	require.NotContains(t, remoteText, "remote-password-secret")
	require.NotContains(t, remoteText, "remote-totp-secret")
	require.NotContains(t, remoteText, "secret=value")
}

func TestDetailFromConflictDetailShowsMissingRemoteClearly(t *testing.T) {
	local := vault.Item{ID: "item-1", Name: "Local Only", Type: vault.ItemTypeSecureNote, Notes: "secret note"}

	d := DetailFromConflictDetail(coresync.ConflictDetail{
		Conflict:      coresync.Conflict{ID: "conflict-1", ItemID: "item-1", Reason: coresync.ConflictRemoteDeleted},
		LocalItem:     &local,
		RemoteDeleted: true,
	})

	require.Len(t, d.ConflictSummaries, 2)
	require.Equal(t, "Remote", d.ConflictSummaries[1].Label)
	require.Equal(t, "Remote item was deleted", d.ConflictSummaries[1].MissingText)
	require.NotContains(t, conflictSummaryText(d.ConflictSummaries[0]), "secret note")
}

func conflictSummaryText(summary ConflictItemSummary) string {
	var b strings.Builder
	b.WriteString(summary.Label)
	b.WriteString("\n")
	b.WriteString(summary.MissingText)
	for _, field := range summary.Fields {
		b.WriteString("\n")
		b.WriteString(field.Label)
		b.WriteString(": ")
		b.WriteString(field.Value)
	}
	return b.String()
}
