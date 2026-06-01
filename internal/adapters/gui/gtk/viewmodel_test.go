package gtk

import (
	"testing"

	corevault "github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
	"github.com/stretchr/testify/require"
)

func TestRowFromItem_Login_ExcludesPasswordAndTOTP(t *testing.T) {
	item := corevault.Item{
		ID:   "login-1",
		Name: "My Login",
		Type: corevault.ItemTypeLogin,
		Login: &corevault.Login{
			Username: "user@example.com",
			Password: "supersecret",
			TOTP:     "JBSWY3DPEHPK3PXP",
			URIs: []corevault.URI{
				{URI: "https://example.com/login"},
			},
		},
	}

	vm := RowFromItem(item)

	require.Equal(t, "My Login", vm.Title)
	require.Contains(t, vm.Subtitle, "user@example.com")
	require.Contains(t, vm.Subtitle, "example.com")
	require.NotContains(t, vm.Subtitle, "supersecret")
	require.NotContains(t, vm.Subtitle, "JBSWY3DPEHPK3PXP")
}

func TestRowFromItem_Login_WithHostParsing(t *testing.T) {
	item := corevault.Item{
		ID:   "login-2",
		Name: "GitHub",
		Type: corevault.ItemTypeLogin,
		Login: &corevault.Login{
			Username: "octocat",
			URIs: []corevault.URI{
				{URI: "https://github.com/login?redirect=home#section"},
			},
		},
	}

	vm := RowFromItem(item)

	require.Contains(t, vm.Subtitle, "octocat")
	require.Contains(t, vm.Subtitle, "github.com")
	require.NotContains(t, vm.Subtitle, "?redirect=home")
	require.NotContains(t, vm.Subtitle, "#section")
}

func TestRowFromItem_Login_FallbackRawURI(t *testing.T) {
	item := corevault.Item{
		ID:   "login-3",
		Name: "Local",
		Type: corevault.ItemTypeLogin,
		Login: &corevault.Login{
			URIs: []corevault.URI{
				{URI: "http://192.168.1.1:8080/admin?q=test"},
			},
		},
	}

	vm := RowFromItem(item)
	// IP with port parses fine, host returns "192.168.1.1:8080"
	require.Contains(t, vm.Subtitle, "192.168.1.1:8080")
}

func TestRowFromItem_SecureNote_ExcludesBody(t *testing.T) {
	item := corevault.Item{
		ID:   "note-1",
		Name: "My Secret Note",
		Type: corevault.ItemTypeSecureNote,
		SecureNote: &corevault.SecureNote{
			Text: "This is the secret body that must never appear in subtitle",
		},
	}

	vm := RowFromItem(item)

	require.Equal(t, "Secure note", vm.Subtitle)
	require.NotContains(t, vm.Subtitle, "secret body")
}

func TestRowFromItem_Card_ExcludesFullNumberAndCode(t *testing.T) {
	item := corevault.Item{
		ID:   "card-1",
		Name: "My Visa",
		Type: corevault.ItemTypeCard,
		Card: &corevault.Card{
			Brand:  "Visa",
			Number: "4111111111111111",
			Code:   "123",
		},
	}

	vm := RowFromItem(item)

	require.Contains(t, vm.Subtitle, "Visa")
	require.Contains(t, vm.Subtitle, "•••• 1111")
	require.NotContains(t, vm.Subtitle, "4111111111111111")
	require.NotContains(t, vm.Subtitle, "123")
}

func TestRowFromItem_Card_ShortNumber(t *testing.T) {
	item := corevault.Item{
		ID:   "card-2",
		Name: "Short Card",
		Type: corevault.ItemTypeCard,
		Card: &corevault.Card{
			Brand:  "Amex",
			Number: "123",
		},
	}

	vm := RowFromItem(item)

	require.Contains(t, vm.Subtitle, "Amex")
	require.NotContains(t, vm.Subtitle, "••••")
	require.NotContains(t, vm.Subtitle, "123")
}

func TestRowFromItem_Identity_ExcludesSSNPassportLicense(t *testing.T) {
	item := corevault.Item{
		ID:   "identity-1",
		Name: "Alice Identity",
		Type: corevault.ItemTypeIdentity,
		Identity: &corevault.Identity{
			FirstName:      "Alice",
			LastName:       "Smith",
			Email:          "alice@example.com",
			Username:       "alice123",
			SSN:            "999-99-9999",
			PassportNumber: "P123456789",
			LicenseNumber:  "D1234567",
		},
	}

	vm := RowFromItem(item)

	require.Contains(t, vm.Subtitle, "Alice")
	require.Contains(t, vm.Subtitle, "Smith")
	require.Contains(t, vm.Subtitle, "alice@example.com")
	require.Contains(t, vm.Subtitle, "alice123")
	require.NotContains(t, vm.Subtitle, "999-99-9999")
	require.NotContains(t, vm.Subtitle, "P123456789")
	require.NotContains(t, vm.Subtitle, "D1234567")
}

func TestRowFromItem_HiddenCustomFieldsExcluded(t *testing.T) {
	item := corevault.Item{
		ID:   "field-1",
		Name: "Item with fields",
		Type: corevault.ItemTypeLogin,
		Login: &corevault.Login{
			Username: "test",
			URIs: []corevault.URI{
				{URI: "https://example.com"},
			},
		},
		Fields: []corevault.Field{
			{Name: "visible", Value: "visible-value", Hidden: false},
			{Name: "hidden", Value: "hidden-value", Hidden: true},
		},
	}

	vm := RowFromItem(item)
	// Row subtitle only uses type-specific fields, not custom fields
	require.Contains(t, vm.Subtitle, "test")
	require.NotContains(t, vm.Subtitle, "hidden-value")
}

func TestRowFromItem_Badge(t *testing.T) {
	item := corevault.Item{
		ID:         "badge-1",
		Name:       "Badge Test",
		Type:       corevault.ItemTypeLogin,
		Favorite:   true,
		Deleted:    true,
		SyncStatus: corevault.SyncStatusPending,
		Login:      &corevault.Login{Username: "test"},
	}

	vm := RowFromItem(item)

	require.Contains(t, vm.Badge, "Deleted")
	require.Contains(t, vm.Badge, "Pending")
	require.Contains(t, vm.Badge, "★")
}

func TestRowsFromScoredItems(t *testing.T) {
	items := []corevault.ScoredItem{
		{
			Item: corevault.Item{
				ID:   "1",
				Name: "First",
				Type: corevault.ItemTypeLogin,
				Login: &corevault.Login{
					Username: "user1",
				},
			},
			Score: 100,
		},
		{
			Item: corevault.Item{
				ID:   "2",
				Name: "Second",
				Type: corevault.ItemTypeLogin,
				Login: &corevault.Login{
					Username: "user2",
				},
			},
			Score: 50,
		},
	}

	vms := RowsFromScoredItems(items)
	require.Len(t, vms, 2)
	require.Equal(t, "First", vms[0].Title)
	require.Equal(t, "Second", vms[1].Title)
}

func TestRowsFromScoredItems_Nil(t *testing.T) {
	vms := RowsFromScoredItems(nil)
	require.Nil(t, vms)
}

// --- StatusEvent mapping ---

func TestStatusFromEvent_SyncChecking(t *testing.T) {
	evt := in.Event{Kind: in.SyncChecking}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Checking for updates…", vm.Text)
	require.True(t, vm.Syncing)
}

func TestStatusFromEvent_SyncUpdated(t *testing.T) {
	evt := in.Event{Kind: in.SyncUpdated}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Vault synced", vm.Text)
	require.False(t, vm.Syncing)
}

func TestStatusFromEvent_SyncFailed(t *testing.T) {
	evt := in.Event{Kind: in.SyncFailed, Message: "network error"}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Network unavailable", vm.Text)
	require.False(t, vm.Syncing)
	require.Equal(t, "Network unavailable", vm.Error)
}

func TestStatusFromEvent_SyncFailed_RawBackendRegression(t *testing.T) {
	evt := in.Event{Kind: in.SyncFailed, Message: "remote sync failed: bitwarden: decryption failed op=crypto.DecryptCipher code=decryption_failed message=failed to decrypt cipher field"}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Vault could not be decrypted", vm.Text)
	require.False(t, vm.Syncing)
	require.Equal(t, "Vault could not be decrypted", vm.Error)
}

func TestStatusFromEvent_SyncFailed_EmptyMessage(t *testing.T) {
	evt := in.Event{Kind: in.SyncFailed}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Sync failed", vm.Text)
	require.False(t, vm.Syncing)
	require.Equal(t, "Sync failed", vm.Error)
}

func TestStatusFromEvent_MutationPending(t *testing.T) {
	evt := in.Event{Kind: in.MutationPending, Count: 3}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Saving…", vm.Text)
	require.True(t, vm.Syncing)
	require.Equal(t, 3, vm.PendingCount)
}

func TestStatusFromEvent_ConflictDetected(t *testing.T) {
	evt := in.Event{Kind: in.ConflictDetected, Count: 2}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Conflict detected", vm.Text)
	require.False(t, vm.Syncing)
	require.Equal(t, 2, vm.ConflictCount)
}

func TestStatusFromEvent_CacheLoaded(t *testing.T) {
	evt := in.Event{Kind: in.CacheLoaded}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Cache loaded — checking sync…", vm.Text)
	require.True(t, vm.Offline)
	require.True(t, vm.Syncing)
}

func TestStatusFromEvent_IndexReady(t *testing.T) {
	evt := in.Event{Kind: in.IndexReady}
	vm := StatusFromEvent(evt)
	require.Equal(t, "Search ready", vm.Text)
	require.True(t, vm.Offline)
	require.False(t, vm.Syncing)
}

// --- DetailFromItem ---

func TestDetailFromItem_Login(t *testing.T) {
	item := corevault.Item{
		ID:   "det-login-1",
		Name: "My Login",
		Type: corevault.ItemTypeLogin,
		Login: &corevault.Login{
			Username: "user@example.com",
			Password: "secret",
			TOTP:     "totp-secret",
			URIs: []corevault.URI{
				{URI: "https://example.com"},
			},
		},
	}

	vm := DetailFromItem(item)
	require.Equal(t, "user@example.com", vm.Username)
	require.Len(t, vm.URIs, 1)
	require.True(t, vm.PasswordPresent)
	require.True(t, vm.TOTPPresent)
	// No secret values leaked into non-sensitive fields
	require.NotContains(t, vm.Username, "secret")
	require.NotContains(t, vm.Username, "totp")
	for _, uri := range vm.URIs {
		require.NotContains(t, uri, "totp")
	}
}

func TestDetailFromItem_Card(t *testing.T) {
	item := corevault.Item{
		ID:   "det-card-1",
		Name: "My Card",
		Type: corevault.ItemTypeCard,
		Card: &corevault.Card{
			CardholderName: "Alice",
			Brand:          "Visa",
			Number:         "4111111111111111",
			Code:           "123",
			ExpMonth:       "12",
			ExpYear:        "2028",
		},
	}

	vm := DetailFromItem(item)
	require.Equal(t, "Alice", vm.CardholderName)
	require.Equal(t, "Visa", vm.Brand)
	require.Equal(t, "1111", vm.Last4)
	require.True(t, vm.CodePresent)
	require.Equal(t, "12", vm.ExpMonth)
	require.Equal(t, "2028", vm.ExpYear)
}

func TestDetailFromItem_Identity(t *testing.T) {
	item := corevault.Item{
		ID:   "det-identity-1",
		Name: "Alice Identity",
		Type: corevault.ItemTypeIdentity,
		Identity: &corevault.Identity{
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

	vm := DetailFromItem(item)
	require.Contains(t, vm.IdentityName, "Dr.")
	require.Contains(t, vm.IdentityName, "Alice")
	require.Contains(t, vm.IdentityName, "M")
	require.Contains(t, vm.IdentityName, "Smith")
	require.Equal(t, "alice@example.com", vm.IdentityEmail)
	require.True(t, vm.HasSSN)
	require.True(t, vm.HasPassport)
	require.True(t, vm.HasLicense)
}

func TestDetailFromItem_HiddenFieldsExcluded(t *testing.T) {
	item := corevault.Item{
		ID:   "det-fields-1",
		Name: "Fields",
		Type: corevault.ItemTypeLogin,
		Login: &corevault.Login{
			Username: "test",
		},
		Fields: []corevault.Field{
			{Name: "visible-note", Value: "visible", Hidden: false},
			{Name: "hidden-pin", Value: "1234", Hidden: true},
		},
	}

	vm := DetailFromItem(item)
	require.Len(t, vm.Fields, 1)
	require.Equal(t, "visible-note", vm.Fields[0].Name)
	require.Equal(t, "visible", vm.Fields[0].Value)
}
