package omnibox

import (
	"strconv"
	"strings"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/gui/display"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// Detail represents a vault item detail with safe display fields.
// Sensitive values are never included; presence is indicated by booleans.
type Detail struct {
	ID       string
	Title    string
	Type     string
	Username string
	URI      string

	NotesPresent      bool
	PasswordPresent   bool
	TOTPPresent       bool
	Attachments       []string
	Conflict          bool
	ConflictID        string
	ConflictOnly      bool
	ConflictSummaries []ConflictItemSummary
	Pending           bool
	Deleted           bool

	// Login safe fields
	URIs []string

	// Card safe fields
	CardBrand string
	CardLast4 string

	// Identity safe fields
	IdentityName string
}

// ConflictSummaryField is one safe, displayable field in a conflict side.
type ConflictSummaryField struct {
	Label string
	Value string
}

// ConflictItemSummary is a safe summary for one side of a conflict.
type ConflictItemSummary struct {
	Label       string
	Fields      []ConflictSummaryField
	MissingText string
}

// ConflictResolutionAction describes one safe UI action for a conflicted item.
type ConflictResolutionAction struct {
	Label      string
	Resolution coresync.ConflictResolution
}

// ConflictResolutionActions returns the available resolution actions for a
// conflicted detail. It returns none until the item carries a concrete
// conflict ID that ResolveConflict can use.
func ConflictResolutionActions(detail Detail) []ConflictResolutionAction {
	if !detail.Conflict || detail.ConflictID == "" {
		return nil
	}
	return []ConflictResolutionAction{
		{Label: "Keep local", Resolution: coresync.ResolutionKeepLocal},
		{Label: "Use remote", Resolution: coresync.ResolutionKeepRemote},
		{Label: "Duplicate local", Resolution: coresync.ResolutionDuplicateLocal},
	}
}

// DetailFromConflictDetail converts a conflict detail into a safe UI detail.
func DetailFromConflictDetail(conflictDetail coresync.ConflictDetail) Detail {
	item := firstAvailableConflictItem(conflictDetail)
	d := Detail{
		ID:           conflictDetail.Conflict.ItemID,
		Title:        "Conflicted item",
		Type:         "Conflict",
		Conflict:     true,
		ConflictID:   conflictDetail.Conflict.ID,
		ConflictOnly: true,
	}
	if item != nil {
		d.ID = item.ID
		if item.Name != "" {
			d.Title = item.Name
		}
		if item.Type != "" {
			d.Type = string(item.Type)
		}
	}
	d.ConflictSummaries = []ConflictItemSummary{
		conflictItemSummary("Local", conflictDetail.LocalItem, conflictDetail.LocalDeleted, missingLocalConflictText(conflictDetail.Conflict.Reason)),
		conflictItemSummary("Remote", conflictDetail.RemoteItem, conflictDetail.RemoteDeleted, missingRemoteConflictText(conflictDetail.Conflict.Reason)),
	}
	return d
}

func firstAvailableConflictItem(conflictDetail coresync.ConflictDetail) *vault.Item {
	if conflictDetail.LocalItem != nil {
		return conflictDetail.LocalItem
	}
	return conflictDetail.RemoteItem
}

func conflictItemSummary(label string, item *vault.Item, deleted bool, missingText string) ConflictItemSummary {
	summary := ConflictItemSummary{Label: label}
	if deleted {
		summary.MissingText = missingText
		return summary
	}
	if item == nil {
		summary.MissingText = "Item snapshot unavailable"
		return summary
	}
	addField := func(fieldLabel, value string) {
		if strings.TrimSpace(value) != "" {
			summary.Fields = append(summary.Fields, ConflictSummaryField{Label: fieldLabel, Value: value})
		}
	}

	addField("Name", item.Name)
	addField("Type", string(item.Type))
	if item.Deleted {
		addField("Deleted", "yes")
	}
	if item.Notes != "" || (item.SecureNote != nil && item.SecureNote.Text != "") {
		addField("Notes", "present (hidden)")
	}

	switch item.Type {
	case vault.ItemTypeLogin:
		if item.Login != nil {
			addField("Username", item.Login.Username)
			if len(item.Login.URIs) > 0 {
				uris := make([]string, 0, len(item.Login.URIs))
				for _, uri := range item.Login.URIs {
					if safeURI := display.SafeURI(uri.URI); safeURI != "" {
						uris = append(uris, safeURI)
					}
				}
				addField("URI", strings.Join(uris, ", "))
			}
			if item.Login.Password != "" {
				addField("Password", "stored (hidden)")
			}
			if item.Login.TOTP != "" {
				addField("TOTP", "stored (hidden)")
			}
		}
	case vault.ItemTypeCard:
		if item.Card != nil {
			addField("Cardholder", item.Card.CardholderName)
			addField("Brand", item.Card.Brand)
			if last4 := display.SafeLast4(item.Card.Number); last4 != "" {
				addField("Number", "•••• "+last4)
			} else if item.Card.Number != "" {
				addField("Number", "stored (hidden)")
			}
			if item.Card.ExpMonth != "" || item.Card.ExpYear != "" {
				addField("Expires", strings.Trim(strings.Join([]string{item.Card.ExpMonth, item.Card.ExpYear}, "/"), "/"))
			}
			if item.Card.Code != "" {
				addField("Security code", "stored (hidden)")
			}
		}
	case vault.ItemTypeIdentity:
		if item.Identity != nil {
			addField("Identity name", display.BuildIdentityName(item.Identity))
			addField("Email", item.Identity.Email)
			addField("Username", item.Identity.Username)
			addField("Phone", item.Identity.Phone)
			addField("Company", item.Identity.Company)
		}
	}

	visibleFieldNames := make([]string, 0, len(item.Fields))
	hiddenCount := 0
	for _, field := range item.Fields {
		if field.Hidden {
			hiddenCount++
			continue
		}
		if field.Name != "" {
			visibleFieldNames = append(visibleFieldNames, field.Name)
		}
	}
	addField("Visible custom fields", strings.Join(visibleFieldNames, ", "))
	if hiddenCount > 0 {
		addField("Hidden custom fields", strconv.Itoa(hiddenCount))
	}

	attachmentNames := make([]string, 0, len(item.Attachments))
	for _, attachment := range item.Attachments {
		if attachment.FileName != "" {
			attachmentNames = append(attachmentNames, attachment.FileName)
		}
	}
	addField("Attachments", strings.Join(attachmentNames, ", "))
	return summary
}

func missingLocalConflictText(reason coresync.ConflictReason) string {
	if reason == coresync.ConflictLocalDeletedRemoteModified {
		return "Local item was deleted"
	}
	return "Local item snapshot unavailable"
}

func missingRemoteConflictText(reason coresync.ConflictReason) string {
	if reason == coresync.ConflictRemoteDeleted {
		return "Remote item was deleted"
	}
	return "Remote item snapshot unavailable"
}

// DetailFromItem converts a vault Item to a safe Detail.
func DetailFromItem(item vault.Item) Detail {
	d := Detail{
		ID:           item.ID,
		Title:        item.Name,
		Type:         string(item.Type),
		Conflict:     item.SyncStatus == vault.SyncStatusConflict,
		ConflictID:   item.ConflictID,
		Pending:      item.SyncStatus == vault.SyncStatusPending,
		Deleted:      item.Deleted,
		NotesPresent: item.Notes != "",
	}

	switch item.Type {
	case vault.ItemTypeLogin:
		if item.Login != nil {
			d.Username = item.Login.Username
			if len(item.Login.URIs) > 0 {
				d.URI = item.Login.URIs[0].URI
			}
			for _, u := range item.Login.URIs {
				d.URIs = append(d.URIs, u.URI)
			}
			d.PasswordPresent = item.Login.Password != ""
			d.TOTPPresent = item.Login.TOTP != ""
		}

	case vault.ItemTypeCard:
		if item.Card != nil {
			d.CardBrand = item.Card.Brand
			d.CardLast4 = display.SafeLast4(item.Card.Number)
			// CodePresent is implied by presence but not exposed as a field.
			// Last4 only, never full number or code.
		}

	case vault.ItemTypeIdentity:
		if item.Identity != nil {
			d.IdentityName = display.BuildIdentityName(item.Identity)
			// SSN, PassportNumber, LicenseNumber are intentionally NOT exposed.
		}
	}

	// Attachment file names only (no URLs/content).
	for _, a := range item.Attachments {
		d.Attachments = append(d.Attachments, a.FileName)
	}

	return d
}
