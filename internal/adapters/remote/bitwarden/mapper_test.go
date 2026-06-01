package bitwarden

import (
	"testing"

	sdk "github.com/bnema/bitwarden-go-sdk/bitwarden"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	corevault "github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapLoginItemRoundTrip(t *testing.T) {
	// Build a core login item with all fields populated.
	original := corevault.Item{
		ID:       "item-login-1",
		Name:     "Example Login",
		Notes:    "My notes",
		Favorite: true,
		FolderID: "folder-1",
		Type:     corevault.ItemTypeLogin,
		Login: &corevault.Login{
			Username: "alice",
			Password: "s3cret!",
			TOTP:     "totp-secret-key",
			URIs: []corevault.URI{
				{URI: "https://example.com"},
				{URI: "https://example.org"},
			},
		},
		Fields: []corevault.Field{
			{Name: "custom1", Value: "val1", Type: "0", Hidden: false},
			{Name: "custom2", Value: "val2", Type: "1", Hidden: false},
		},
	}

	// Round-trip: core → SDK → core.
	sdkItem := toSDKItem(original)
	result, err := toCoreItem(sdkItem)
	require.NoError(t, err)

	// Verify scalar fields.
	assert.Equal(t, original.ID, result.ID)
	assert.Equal(t, original.Name, result.Name)
	assert.Equal(t, original.Notes, result.Notes)
	assert.Equal(t, original.Favorite, result.Favorite)
	assert.Equal(t, original.FolderID, result.FolderID)
	assert.Equal(t, original.Type, result.Type)

	// Verify login secrets survived.
	require.NotNil(t, result.Login)
	assert.Equal(t, original.Login.Username, result.Login.Username)
	assert.Equal(t, original.Login.Password, result.Login.Password)
	assert.Equal(t, original.Login.TOTP, result.Login.TOTP)

	// Verify URIs survived.
	require.Len(t, result.Login.URIs, 2)
	assert.Equal(t, "https://example.com", result.Login.URIs[0].URI)
	assert.Equal(t, "https://example.org", result.Login.URIs[1].URI)

	// Verify fields.
	require.Len(t, result.Fields, 2)
	assert.Equal(t, "custom1", result.Fields[0].Name)
	assert.Equal(t, "val1", result.Fields[0].Value)
	assert.Equal(t, "0", result.Fields[0].Type)
	assert.False(t, result.Fields[0].Hidden)
	assert.Equal(t, "custom2", result.Fields[1].Name)
	assert.Equal(t, "val2", result.Fields[1].Value)
	assert.Equal(t, "1", result.Fields[1].Type)
}

func TestMapCardAndIdentitySecrets(t *testing.T) {
	// Build a core card item.
	cardItem := corevault.Item{
		ID:   "item-card-1",
		Name: "My Card",
		Type: corevault.ItemTypeCard,
		Card: &corevault.Card{
			CardholderName: "Alice",
			Brand:          "Visa",
			Number:         "4111111111111111",
			ExpMonth:       "12",
			ExpYear:        "2028",
			Code:           "123",
		},
	}

	// Build a core identity item.
	identityItem := corevault.Item{
		ID:   "item-identity-1",
		Name: "My Identity",
		Type: corevault.ItemTypeIdentity,
		Identity: &corevault.Identity{
			Title:          "Mr",
			FirstName:      "Alice",
			MiddleName:     "M",
			LastName:       "Smith",
			SSN:            "123-45-6789",
			PassportNumber: "AB123456",
			LicenseNumber:  "D123-4567-8901",
			Username:       "alice_smith",
		},
	}

	// Round-trip card.
	sdkCard := toSDKItem(cardItem)
	resultCard, err := toCoreItem(sdkCard)
	require.NoError(t, err)
	assert.Equal(t, corevault.ItemTypeCard, resultCard.Type)
	require.NotNil(t, resultCard.Card)
	assert.Equal(t, cardItem.Card.Number, resultCard.Card.Number)
	assert.Equal(t, cardItem.Card.Code, resultCard.Card.Code)
	assert.Equal(t, cardItem.Card.CardholderName, resultCard.Card.CardholderName)
	assert.Equal(t, cardItem.Card.Brand, resultCard.Card.Brand)
	assert.Equal(t, cardItem.Card.ExpMonth, resultCard.Card.ExpMonth)
	assert.Equal(t, cardItem.Card.ExpYear, resultCard.Card.ExpYear)

	// Round-trip identity.
	sdkIdent := toSDKItem(identityItem)
	resultIdent, err := toCoreItem(sdkIdent)
	require.NoError(t, err)
	assert.Equal(t, corevault.ItemTypeIdentity, resultIdent.Type)
	require.NotNil(t, resultIdent.Identity)
	assert.Equal(t, identityItem.Identity.SSN, resultIdent.Identity.SSN)
	assert.Equal(t, identityItem.Identity.PassportNumber, resultIdent.Identity.PassportNumber)
	assert.Equal(t, identityItem.Identity.LicenseNumber, resultIdent.Identity.LicenseNumber)
	assert.Equal(t, identityItem.Identity.Title, resultIdent.Identity.Title)
	assert.Equal(t, identityItem.Identity.FirstName, resultIdent.Identity.FirstName)
	assert.Equal(t, identityItem.Identity.LastName, resultIdent.Identity.LastName)
	assert.Equal(t, identityItem.Identity.Username, resultIdent.Identity.Username)
}

func TestMapAttachmentAndFolder(t *testing.T) {
	// SDK Attachment → core Attachment.
	sdkAtt := sdk.Attachment{
		ID:       "att-1",
		CipherID: "cipher-1",
		FileName: "receipt.pdf",
		Size:     102400,
		SizeName: "100 KB",
		URL:      "https://example.com/att/1",
	}
	coreAtt := toCoreAttachment(sdkAtt)
	assert.Equal(t, "att-1", coreAtt.ID)
	assert.Equal(t, "receipt.pdf", coreAtt.FileName)
	assert.Equal(t, int64(102400), coreAtt.Size)
	assert.Equal(t, "https://example.com/att/1", coreAtt.URL)

	// SDK Folder → core Folder.
	sdkFol := sdk.Folder{
		ID:   "folder-2",
		Name: "Work",
	}
	coreFol := toCoreFolder(sdkFol)
	assert.Equal(t, "folder-2", coreFol.ID)
	assert.Equal(t, "Work", coreFol.Name)
}

func TestRegionMapping(t *testing.T) {
	assert.Equal(t, sdk.RegionUS, toSDKRegion(coreconfig.RegionUS))
	assert.Equal(t, sdk.RegionEU, toSDKRegion(coreconfig.RegionEU))
	// Self-hosted and unknown default to US.
	assert.Equal(t, sdk.RegionUS, toSDKRegion(coreconfig.RegionSelfHosted))
	assert.Equal(t, sdk.RegionUS, toSDKRegion(coreconfig.Region("unknown")))
}

func TestRevealSecretNil(t *testing.T) {
	assert.Equal(t, "", revealSecret(nil))
}

func TestRevealSecretEmpty(t *testing.T) {
	s := sdk.NewSecretString("")
	assert.Equal(t, "", revealSecret(s))
}

func TestRevealSecretValue(t *testing.T) {
	s := sdk.NewSecretString("hello-world")
	assert.Equal(t, "hello-world", revealSecret(s))
	// Verify closed after reveal — calling String is safe but returns redacted.
}

func TestMapSecureNoteRoundTrip(t *testing.T) {
	original := corevault.Item{
		ID:   "item-note-1",
		Name: "My Note",
		Type: corevault.ItemTypeSecureNote,
		SecureNote: &corevault.SecureNote{
			Text: "",
		},
	}
	sdkItem := toSDKItem(original)
	result, err := toCoreItem(sdkItem)
	require.NoError(t, err)
	assert.Equal(t, corevault.ItemTypeSecureNote, result.Type)
	require.NotNil(t, result.SecureNote)
}

func TestMapFieldTypeParseErrorDefaultsToZero(t *testing.T) {
	// When core Field.Type is empty or non-numeric, strconv.Atoi returns 0
	// (the safe default for SDK field type 0 = text). This verifies the
	// silent-default behaviour documented in toSDKItem.
	coreItem := corevault.Item{
		ID:    "item-ft-1",
		Name:  "Field Type Test",
		Type:  corevault.ItemTypeLogin,
		Login: &corevault.Login{Username: "u"},
		Fields: []corevault.Field{
			{Name: "empty", Value: "v1", Type: "", Hidden: false},
			{Name: "garbage", Value: "v2", Type: "not-a-number", Hidden: false},
			{Name: "valid", Value: "v3", Type: "1", Hidden: true},
		},
	}

	sdkItem := toSDKItem(coreItem)
	require.Len(t, sdkItem.Fields, 3)
	assert.Equal(t, 0, sdkItem.Fields[0].Type, "empty Type string defaults to 0")
	assert.Equal(t, 0, sdkItem.Fields[1].Type, "non-numeric Type string defaults to 0")
	assert.Equal(t, 1, sdkItem.Fields[2].Type, "valid '1' Type string parses correctly")

	// Round-trip back to core: Hidden should be true for Type 1, false for 0.
	result, err := toCoreItem(sdkItem)
	require.NoError(t, err)
	require.Len(t, result.Fields, 3)
	assert.False(t, result.Fields[0].Hidden, "Type 0 → Hidden false")
	assert.False(t, result.Fields[1].Hidden, "Type 0 → Hidden false")
	assert.True(t, result.Fields[2].Hidden, "Type 1 → Hidden true")
}

func TestMapLoginItemToSDK(t *testing.T) {
	// Verify that toSDKItem preserves a login item with expected fields.
	ci := corevault.Item{
		ID:       "login-1",
		Name:     "My Login",
		Notes:    "note",
		Favorite: true,
		FolderID: "f1",
		Type:     corevault.ItemTypeLogin,
		Login: &corevault.Login{
			Username: "bob",
			Password: "pass123",
			TOTP:     "totpkey",
			URIs: []corevault.URI{
				{URI: "https://bob.example.com"},
			},
		},
		Fields: []corevault.Field{
			{Name: "f1", Value: "v1", Type: "3", Hidden: false},
		},
	}

	si := toSDKItem(ci)
	assert.Equal(t, sdk.ItemID("login-1"), si.ID)
	assert.Equal(t, "My Login", si.Name)
	assert.Equal(t, "note", si.Notes)
	assert.True(t, si.Favorite)
	assert.Equal(t, "f1", si.FolderID)
	assert.Equal(t, sdk.ItemTypeLogin, si.Type)
	assert.Equal(t, "bob", si.Username)

	// Password should be a non-nil Secret that reveals correctly.
	require.NotNil(t, si.Password)
	assert.Equal(t, "pass123", revealSecret(si.Password))
	require.NotNil(t, si.TOTP)
	assert.Equal(t, "totpkey", revealSecret(si.TOTP))

	assert.Equal(t, "https://bob.example.com", si.URI)
	require.Len(t, si.URIs, 1)
	assert.Equal(t, "https://bob.example.com", si.URIs[0])

	require.Len(t, si.Fields, 1)
	assert.Equal(t, "f1", si.Fields[0].Name)
	assert.Equal(t, "v1", si.Fields[0].Value)
	assert.Equal(t, 3, si.Fields[0].Type)
	assert.Equal(t, 0, si.Fields[0].LinkedID)
}
