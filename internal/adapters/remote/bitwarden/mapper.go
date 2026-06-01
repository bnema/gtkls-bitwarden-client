// Package bitwarden implements the RemoteVault outbound port using the
// Bitwarden Go SDK (github.com/bnema/bitwarden-go-sdk/bitwarden).
package bitwarden

import (
	"fmt"
	"strconv"

	sdk "github.com/bnema/bitwarden-go-sdk/bitwarden"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	corevault "github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// revealSecret safely reveals a *sdk.Secret, returning the plaintext string.
// Returns empty string on nil or error. The secret is properly closed.
func revealSecret(secret *sdk.Secret) string {
	if secret == nil {
		return ""
	}
	revealed, err := secret.Reveal()
	if err != nil {
		_ = secret.Close()
		return ""
	}
	val := revealed.String()
	_ = revealed.Close()
	_ = secret.Close()
	return val
}

// toCoreItem maps an SDK Item to a core vault Item.
func toCoreItem(item sdk.Item) (corevault.Item, error) {
	ci := corevault.Item{
		ID:       string(item.ID),
		Name:     item.Name,
		Notes:    item.Notes,
		Favorite: item.Favorite,
		FolderID: item.FolderID,
	}

	switch item.Type {
	case sdk.ItemTypeLogin:
		ci.Type = corevault.ItemTypeLogin
		login := &corevault.Login{
			Username: item.Username,
			Password: revealSecret(item.Password),
			TOTP:     revealSecret(item.TOTP),
		}
		// SDK stores the first URI in both URI and URIs[0]; deduplicate.
		switch {
		case len(item.URIs) > 0:
			login.URIs = make([]corevault.URI, len(item.URIs))
			for i, u := range item.URIs {
				login.URIs[i] = corevault.URI{URI: u}
			}
		case item.URI != "":
			login.URIs = []corevault.URI{{URI: item.URI}}
		}
		ci.Login = login

	case sdk.ItemTypeSecureNote:
		ci.Type = corevault.ItemTypeSecureNote
		// Notes holds the secure note body; mirror into SecureNote.Text for
		// SDK round-trip fidelity per the canonical semantics documented on
		// corevault.SecureNote.
		ci.SecureNote = &corevault.SecureNote{Text: item.Notes}

	case sdk.ItemTypeCard:
		ci.Type = corevault.ItemTypeCard
		if item.Card != nil {
			ci.Card = &corevault.Card{
				CardholderName: item.Card.CardholderName,
				Brand:          item.Card.Brand,
				ExpMonth:       item.Card.ExpMonth,
				ExpYear:        item.Card.ExpYear,
				Number:         revealSecret(item.Card.Number),
				Code:           revealSecret(item.Card.Code),
			}
		}

	case sdk.ItemTypeIdentity:
		ci.Type = corevault.ItemTypeIdentity
		if item.Identity != nil {
			ci.Identity = &corevault.Identity{
				Title:          item.Identity.Title,
				FirstName:      item.Identity.FirstName,
				MiddleName:     item.Identity.MiddleName,
				LastName:       item.Identity.LastName,
				Address1:       item.Identity.Address1,
				Address2:       item.Identity.Address2,
				Address3:       item.Identity.Address3,
				City:           item.Identity.City,
				State:          item.Identity.State,
				PostalCode:     item.Identity.PostalCode,
				Country:        item.Identity.Country,
				Company:        item.Identity.Company,
				Email:          item.Identity.Email,
				Phone:          item.Identity.Phone,
				Username:       item.Identity.Username,
				SSN:            revealSecret(item.Identity.SSN),
				PassportNumber: revealSecret(item.Identity.PassportNumber),
				LicenseNumber:  revealSecret(item.Identity.LicenseNumber),
			}
		}
	}

	// Map fields: SDK Type int → core Type string (decimal).
	// SDK field types: 0 = text, 1 = hidden (boolean), 2 = linked.
	// Map Hidden: SDK Type == 1 → Hidden = true.
	if len(item.Fields) > 0 {
		ci.Fields = make([]corevault.Field, len(item.Fields))
		for i, f := range item.Fields {
			ci.Fields[i] = corevault.Field{
				Name:   f.Name,
				Value:  f.Value,
				Type:   fmt.Sprintf("%d", f.Type),
				Hidden: f.Type == 1,
			}
		}
	}

	return ci, nil
}

// toSDKItem maps a core vault Item to an SDK Item.
func toSDKItem(item corevault.Item) sdk.Item {
	si := sdk.Item{
		ID:       sdk.ItemID(item.ID),
		Name:     item.Name,
		Notes:    item.Notes,
		Favorite: item.Favorite,
		FolderID: item.FolderID,
	}

	switch item.Type {
	case corevault.ItemTypeLogin:
		si.Type = sdk.ItemTypeLogin
		if item.Login != nil {
			si.Username = item.Login.Username
			if item.Login.Password != "" {
				si.Password = sdk.NewSecretString(item.Login.Password)
			}
			if item.Login.TOTP != "" {
				si.TOTP = sdk.NewSecretString(item.Login.TOTP)
			}
			if len(item.Login.URIs) > 0 {
				si.URI = item.Login.URIs[0].URI
				si.URIs = make([]string, len(item.Login.URIs))
				for i, u := range item.Login.URIs {
					si.URIs[i] = u.URI
				}
			}
		}

	case corevault.ItemTypeSecureNote:
		si.Type = sdk.ItemTypeSecureNote

	case corevault.ItemTypeCard:
		si.Type = sdk.ItemTypeCard
		if item.Card != nil {
			card := &sdk.Card{
				CardholderName: item.Card.CardholderName,
				Brand:          item.Card.Brand,
				ExpMonth:       item.Card.ExpMonth,
				ExpYear:        item.Card.ExpYear,
			}
			if item.Card.Number != "" {
				card.Number = sdk.NewSecretString(item.Card.Number)
			}
			if item.Card.Code != "" {
				card.Code = sdk.NewSecretString(item.Card.Code)
			}
			si.Card = card
		}

	case corevault.ItemTypeIdentity:
		si.Type = sdk.ItemTypeIdentity
		if item.Identity != nil {
			ident := &sdk.Identity{
				Title:      item.Identity.Title,
				FirstName:  item.Identity.FirstName,
				MiddleName: item.Identity.MiddleName,
				LastName:   item.Identity.LastName,
				Address1:   item.Identity.Address1,
				Address2:   item.Identity.Address2,
				Address3:   item.Identity.Address3,
				City:       item.Identity.City,
				State:      item.Identity.State,
				PostalCode: item.Identity.PostalCode,
				Country:    item.Identity.Country,
				Company:    item.Identity.Company,
				Email:      item.Identity.Email,
				Phone:      item.Identity.Phone,
				Username:   item.Identity.Username,
			}
			if item.Identity.SSN != "" {
				ident.SSN = sdk.NewSecretString(item.Identity.SSN)
			}
			if item.Identity.PassportNumber != "" {
				ident.PassportNumber = sdk.NewSecretString(item.Identity.PassportNumber)
			}
			if item.Identity.LicenseNumber != "" {
				ident.LicenseNumber = sdk.NewSecretString(item.Identity.LicenseNumber)
			}
			si.Identity = ident
		}
	}

	// Map fields: core Type string (decimal) → SDK Type int.
	// strconv.Atoi returns 0 on error (empty string, non-numeric), which is
	// the safe default (SDK field type 0 = text). Callers must validate the
	// Type string before round-tripping; an invalid parse silently defaults
	// to text, which preserves data without breaking the sync.
	if len(item.Fields) > 0 {
		si.Fields = make([]sdk.Field, len(item.Fields))
		for i, f := range item.Fields {
			typ, _ := strconv.Atoi(f.Type)
			si.Fields[i] = sdk.Field{
				Name:     f.Name,
				Value:    f.Value,
				Type:     typ,
				LinkedID: 0,
			}
		}
	}

	return si
}

// toCoreFolder maps an SDK Folder to a core vault Folder.
func toCoreFolder(folder sdk.Folder) corevault.Folder {
	return corevault.Folder{
		ID:   folder.ID,
		Name: folder.Name,
	}
}

// toCoreAttachment maps an SDK Attachment to a core vault Attachment.
func toCoreAttachment(att sdk.Attachment) corevault.Attachment {
	return corevault.Attachment{
		ID:       att.ID,
		FileName: att.FileName,
		Size:     att.Size,
		URL:      att.URL,
	}
}

// toSDKRegion maps a core config Region to an SDK Region.
//
// Self-hosted and unknown region values default to US because NewClient
// applies the server URL override (cfg.Bitwarden.ServerURL) for
// self-hosted deployments, making the SDK region token irrelevant. The SDK
// uses the region only to derive the default API base URL, which is
// replaced when a ServerURL is set.
func toSDKRegion(region coreconfig.Region) sdk.Region {
	switch region {
	case coreconfig.RegionUS:
		return sdk.RegionUS
	case coreconfig.RegionEU:
		return sdk.RegionEU
	default:
		return sdk.RegionUS
	}
}
