package omnibox

import (
	"testing"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/stretchr/testify/require"
)

func fieldKeys(fields []FormField) []FieldKey {
	keys := make([]FieldKey, len(fields))
	for i, f := range fields {
		keys[i] = f.Key
	}
	return keys
}

func TestFormFields_PerType(t *testing.T) {
	tests := []struct {
		name       string
		itemType   vault.ItemType
		wantKeys   []FieldKey
		wantSecret []FieldKey
	}{
		{
			name:       "login is ordered for quick entry with optional name last",
			itemType:   vault.ItemTypeLogin,
			wantKeys:   []FieldKey{FieldURI, FieldUser, FieldPass, FieldTOTP, FieldName, FieldNotes},
			wantSecret: []FieldKey{FieldPass, FieldTOTP},
		},
		{
			name:     "secure note",
			itemType: vault.ItemTypeSecureNote,
			wantKeys: []FieldKey{FieldName, FieldNotes},
		},
		{
			name:       "card",
			itemType:   vault.ItemTypeCard,
			wantKeys:   []FieldKey{FieldName, FieldHolder, FieldBrand, FieldNumber, FieldExpMo, FieldExpYr, FieldCode, FieldNotes},
			wantSecret: []FieldKey{FieldNumber, FieldCode},
		},
		{
			name:       "identity",
			itemType:   vault.ItemTypeIdentity,
			wantKeys:   []FieldKey{FieldName, FieldFirstName, FieldLastName, FieldEmail, FieldPhone, FieldIDUser, FieldSSN, FieldPassport, FieldLicense, FieldNotes},
			wantSecret: []FieldKey{FieldSSN, FieldPassport, FieldLicense},
		},
		{
			name:     "unknown type falls back to name and notes",
			itemType: vault.ItemType("other"),
			wantKeys: []FieldKey{FieldName, FieldNotes},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := FormFields(tt.itemType)
			require.Equal(t, tt.wantKeys, fieldKeys(fields))

			var secrets []FieldKey
			seen := map[FieldKey]bool{}
			for _, f := range fields {
				require.NotEmpty(t, f.Label)
				require.False(t, seen[f.Key], "duplicate key %q", f.Key)
				seen[f.Key] = true
				if f.Secret {
					secrets = append(secrets, f.Key)
				}
			}
			require.Equal(t, tt.wantSecret, secrets)
		})
	}
}

func TestEditableItem_FieldSetFieldRoundTrip(t *testing.T) {
	all := []FieldKey{
		FieldName, FieldNotes, FieldURI, FieldUser, FieldPass, FieldTOTP,
		FieldHolder, FieldBrand, FieldNumber, FieldExpMo, FieldExpYr, FieldCode,
		FieldFirstName, FieldLastName, FieldEmail, FieldPhone, FieldIDUser, FieldSSN, FieldPassport, FieldLicense,
	}
	var e EditableItem
	for _, key := range all {
		e.SetField(key, "v-"+string(key))
	}
	seen := map[string]FieldKey{}
	for _, key := range all {
		got := e.Field(key)
		require.Equal(t, "v-"+string(key), got, "key %q", key)
		if other, dup := seen[got]; dup {
			t.Fatalf("keys %q and %q alias the same EditableItem field", key, other)
		}
		seen[got] = key
	}
	require.Equal(t, "", e.Field(FieldKey("nope")))
	e.SetField(FieldKey("nope"), "x") // must not panic or change anything
	require.Equal(t, "v-name", e.Name)
}

func TestFormSession_ValueComesFromItem(t *testing.T) {
	item := vault.Item{
		ID: "i1", Name: "Bank", Type: vault.ItemTypeCard, Notes: "n",
		Card: &vault.Card{CardholderName: "A B", Number: "4111111111111111"},
	}
	s := newFormSession(3, item)
	require.Equal(t, uint64(3), s.ID)
	require.True(t, s.IsUpdate())
	require.Equal(t, "Bank", s.Value(FieldName))
	require.Equal(t, "A B", s.Value(FieldHolder))
	require.Equal(t, "4111111111111111", s.Value(FieldNumber))
	require.Equal(t, "n", s.Value(FieldNotes))
}

func TestFormSession_Build(t *testing.T) {
	tests := []struct {
		name    string
		item    vault.Item
		values  map[FieldKey]string
		wantErr string
		check   func(t *testing.T, got vault.Item)
	}{
		{
			name: "login derives its name and trims",
			item: vault.Item{Type: vault.ItemTypeLogin, Login: &vault.Login{}},
			values: map[FieldKey]string{
				FieldURI: " https://github.com/login ", FieldUser: " octocat ", FieldPass: " pw ", FieldTOTP: " 123 ", FieldName: "", FieldNotes: "n",
			},
			check: func(t *testing.T, got vault.Item) {
				require.Equal(t, "github.com (octocat)", got.Name)
				require.Equal(t, "octocat", got.Login.Username)
				require.Equal(t, " pw ", got.Login.Password, "password whitespace is preserved")
				require.Equal(t, "123", got.Login.TOTP)
				require.Equal(t, "https://github.com/login", got.Login.URIs[0].URI)
				require.Equal(t, "n", got.Notes)
			},
		},
		{
			name:    "login without site, username or name is invalid",
			item:    vault.Item{Type: vault.ItemTypeLogin},
			values:  map[FieldKey]string{FieldPass: "pw"},
			wantErr: "site or username is required",
		},
		{
			name:    "note needs a name",
			item:    vault.Item{Type: vault.ItemTypeSecureNote},
			values:  map[FieldKey]string{FieldName: "  ", FieldNotes: "body"},
			wantErr: "item name is required",
		},
		{
			name:   "note keeps text in both notes and secure note",
			item:   vault.Item{Type: vault.ItemTypeSecureNote},
			values: map[FieldKey]string{FieldName: "Wifi", FieldNotes: "body"},
			check: func(t *testing.T, got vault.Item) {
				require.Equal(t, "Wifi", got.Name)
				require.Equal(t, "body", got.Notes)
				require.Equal(t, "body", got.SecureNote.Text)
			},
		},
		{
			name: "card maps every field",
			item: vault.Item{Type: vault.ItemTypeCard},
			values: map[FieldKey]string{
				FieldName: "Visa", FieldHolder: "A B", FieldBrand: "visa", FieldNumber: "4111", FieldExpMo: "01", FieldExpYr: "2030", FieldCode: "123",
			},
			check: func(t *testing.T, got vault.Item) {
				require.Equal(t, vault.Card{CardholderName: "A B", Brand: "visa", Number: "4111", ExpMonth: "01", ExpYear: "2030", Code: "123"}, *got.Card)
			},
		},
		{
			name: "identity maps every field",
			item: vault.Item{Type: vault.ItemTypeIdentity},
			values: map[FieldKey]string{
				FieldName: "Me", FieldFirstName: "A", FieldLastName: "B", FieldEmail: "e", FieldPhone: "p", FieldIDUser: "u", FieldSSN: "s", FieldPassport: "pp", FieldLicense: "l",
			},
			check: func(t *testing.T, got vault.Item) {
				require.Equal(t, vault.Identity{FirstName: "A", LastName: "B", Email: "e", Phone: "p", Username: "u", SSN: "s", PassportNumber: "pp", LicenseNumber: "l"}, *got.Identity)
			},
		},
		{
			name: "missing keys keep their initial value",
			item: vault.Item{ID: "i1", Name: "Keep", Type: vault.ItemTypeCard, Card: &vault.Card{Number: "4111", Code: "999"}},
			values: map[FieldKey]string{
				FieldName: "Renamed",
			},
			check: func(t *testing.T, got vault.Item) {
				require.Equal(t, "Renamed", got.Name)
				require.Equal(t, "4111", got.Card.Number)
				require.Equal(t, "999", got.Card.Code)
			},
		},
		{
			name: "keys foreign to the item type are ignored",
			item: vault.Item{Type: vault.ItemTypeSecureNote},
			values: map[FieldKey]string{
				FieldName: "N", FieldPass: "leak", FieldNumber: "leak",
			},
			check: func(t *testing.T, got vault.Item) {
				require.Nil(t, got.Login)
				require.Nil(t, got.Card)
				require.NotNil(t, got.SecureNote)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newFormSession(1, tt.item).Build(tt.values)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			tt.check(t, got)
		})
	}
}

func TestNewQuickAddItem(t *testing.T) {
	login := NewQuickAddItem(vault.ItemTypeLogin, "example.com", "pw")
	require.Equal(t, "pw", login.Login.Password)
	require.Equal(t, "example.com", login.Login.URIs[0].URI)

	blank := NewQuickAddItem(vault.ItemTypeLogin, "", "")
	require.NotNil(t, blank.Login)
	require.Empty(t, blank.Login.URIs)

	card := NewQuickAddItem(vault.ItemTypeCard, "example.com", "pw")
	require.Equal(t, vault.ItemTypeCard, card.Type)
	require.Nil(t, card.Login)
}
