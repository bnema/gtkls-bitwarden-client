package omnibox

import (
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// FieldKey identifies one editable form field independent of any widget. The
// view maps widgets to keys; everything else about the form lives here.
type FieldKey string

const (
	FieldName   FieldKey = "name"
	FieldNotes  FieldKey = "notes"
	FieldURI    FieldKey = "uri"
	FieldUser   FieldKey = "username"
	FieldPass   FieldKey = "password"
	FieldTOTP   FieldKey = "totp"
	FieldHolder FieldKey = "card_holder"
	FieldBrand  FieldKey = "card_brand"
	FieldNumber FieldKey = "card_number"
	FieldExpMo  FieldKey = "card_exp_month"
	FieldExpYr  FieldKey = "card_exp_year"
	FieldCode   FieldKey = "card_code"

	FieldFirstName FieldKey = "identity_first_name"
	FieldLastName  FieldKey = "identity_last_name"
	FieldEmail     FieldKey = "identity_email"
	FieldPhone     FieldKey = "identity_phone"
	FieldIDUser    FieldKey = "identity_username"
	FieldSSN       FieldKey = "identity_ssn"
	FieldPassport  FieldKey = "identity_passport"
	FieldLicense   FieldKey = "identity_license"
)

// FormField describes one form field: its key, label, and whether its value is
// secret material that must be masked.
type FormField struct {
	Key    FieldKey
	Label  string
	Secret bool
}

// FormFields returns the fields of the form for an item type, in display order
// (every type includes Name and Notes). Login forms are ordered for quick
// keyboard entry: Site → Username → Password → TOTP, with Name optional and
// auto-derived when left blank. The first field receives initial focus.
func FormFields(t vault.ItemType) []FormField {
	notes := FormField{Key: FieldNotes, Label: "Notes"}
	name := FormField{Key: FieldName, Label: "Name"}
	switch t {
	case vault.ItemTypeLogin:
		return []FormField{
			{Key: FieldURI, Label: "Site / URI"},
			{Key: FieldUser, Label: "Username"},
			{Key: FieldPass, Label: "Password", Secret: true},
			{Key: FieldTOTP, Label: "TOTP (optional)", Secret: true},
			{Key: FieldName, Label: "Name (optional, auto-generated)"},
			notes,
		}
	case vault.ItemTypeCard:
		return []FormField{
			name,
			{Key: FieldHolder, Label: "Cardholder name"},
			{Key: FieldBrand, Label: "Brand"},
			{Key: FieldNumber, Label: "Number", Secret: true},
			{Key: FieldExpMo, Label: "Exp month"},
			{Key: FieldExpYr, Label: "Exp year"},
			{Key: FieldCode, Label: "Code", Secret: true},
			notes,
		}
	case vault.ItemTypeIdentity:
		return []FormField{
			name,
			{Key: FieldFirstName, Label: "First name"},
			{Key: FieldLastName, Label: "Last name"},
			{Key: FieldEmail, Label: "Email"},
			{Key: FieldPhone, Label: "Phone"},
			{Key: FieldIDUser, Label: "Username"},
			{Key: FieldSSN, Label: "SSN", Secret: true},
			{Key: FieldPassport, Label: "Passport number", Secret: true},
			{Key: FieldLicense, Label: "License number", Secret: true},
			notes,
		}
	default:
		return []FormField{name, notes}
	}
}

// Field returns the value of the field identified by key.
func (e EditableItem) Field(key FieldKey) string {
	switch key {
	case FieldName:
		return e.Name
	case FieldNotes:
		return e.Notes
	case FieldURI:
		return e.URI
	case FieldUser:
		return e.Username
	case FieldPass:
		return e.Password
	case FieldTOTP:
		return e.TOTP
	case FieldHolder:
		return e.CardholderName
	case FieldBrand:
		return e.CardBrand
	case FieldNumber:
		return e.CardNumber
	case FieldExpMo:
		return e.CardExpMonth
	case FieldExpYr:
		return e.CardExpYear
	case FieldCode:
		return e.CardCode
	case FieldFirstName:
		return e.IdentityFirstName
	case FieldLastName:
		return e.IdentityLastName
	case FieldEmail:
		return e.IdentityEmail
	case FieldPhone:
		return e.IdentityPhone
	case FieldIDUser:
		return e.IdentityUsername
	case FieldSSN:
		return e.IdentitySSN
	case FieldPassport:
		return e.IdentityPassportNumber
	case FieldLicense:
		return e.IdentityLicenseNumber
	default:
		return ""
	}
}

// SetField sets the field identified by key. Unknown keys are ignored.
func (e *EditableItem) SetField(key FieldKey, value string) {
	switch key {
	case FieldName:
		e.Name = value
	case FieldNotes:
		e.Notes = value
	case FieldURI:
		e.URI = value
	case FieldUser:
		e.Username = value
	case FieldPass:
		e.Password = value
	case FieldTOTP:
		e.TOTP = value
	case FieldHolder:
		e.CardholderName = value
	case FieldBrand:
		e.CardBrand = value
	case FieldNumber:
		e.CardNumber = value
	case FieldExpMo:
		e.CardExpMonth = value
	case FieldExpYr:
		e.CardExpYear = value
	case FieldCode:
		e.CardCode = value
	case FieldFirstName:
		e.IdentityFirstName = value
	case FieldLastName:
		e.IdentityLastName = value
	case FieldEmail:
		e.IdentityEmail = value
	case FieldPhone:
		e.IdentityPhone = value
	case FieldIDUser:
		e.IdentityUsername = value
	case FieldSSN:
		e.IdentitySSN = value
	case FieldPassport:
		e.IdentityPassportNumber = value
	case FieldLicense:
		e.IdentityLicenseNumber = value
	}
}

// FormSession is one open add/edit form. It is created by Controller.OpenForm
// and replaced whenever a form is opened again.
type FormSession struct {
	// ID distinguishes sessions so a late save outcome cannot touch a newer form.
	ID uint64
	// Item is the item being edited; an empty ID means a new item.
	Item vault.Item
	// Fields are the fields to show, in order.
	Fields []FormField
	// Saving is true while a save is in flight; further submits are ignored.
	Saving bool

	initial EditableItem
}

func newFormSession(id uint64, item vault.Item) *FormSession {
	return &FormSession{
		ID:      id,
		Item:    item,
		Fields:  FormFields(item.Type),
		initial: EditableFromItem(item),
	}
}

// Value returns the initial value to show for a field.
func (s *FormSession) Value(key FieldKey) string {
	return s.initial.Field(key)
}

// IsUpdate reports whether submitting updates an existing item.
func (s *FormSession) IsUpdate() bool {
	return s.Item.ID != ""
}

// Build overlays the submitted values onto the edited item, validates the
// result, and returns the item to save. Fields missing from values keep their
// initial value; keys that are not part of this form's fields are ignored.
func (s *FormSession) Build(values map[FieldKey]string) (vault.Item, error) {
	e := s.initial
	for _, f := range s.Fields {
		if v, ok := values[f.Key]; ok {
			e.SetField(f.Key, v)
		}
	}
	if err := ValidateItem(e); err != nil {
		return vault.Item{}, err
	}
	return e.BuildItem(), nil
}

// NewQuickAddItem returns the blank item for the add form. For logins, a
// non-empty site prefills the URI and a non-empty password prefills the
// password.
func NewQuickAddItem(t vault.ItemType, site, password string) vault.Item {
	item := vault.Item{Type: t}
	if t == vault.ItemTypeLogin {
		item.Login = &vault.Login{Password: password}
		if site != "" {
			item.Login.URIs = []vault.URI{{URI: site}}
		}
	}
	return item
}
