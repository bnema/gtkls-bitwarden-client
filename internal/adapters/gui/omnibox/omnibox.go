// Package omnibox provides a keyboard-driven adapter for the GTK omnibox UI.
// Pure state/controller files in this package have no puregotk dependency and
// compile under any build tag.
package omnibox

import "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"

// Mode represents the current view mode of the omnibox.
type Mode int

const (
	ModeUnlock Mode = iota
	ModePINUnlock
	ModeKeyringError
	ModeSearch
	ModeDetail
	ModeForm
)

// Action represents a user action that can be taken on a row.
type Action int

const (
	ActionNone Action = iota
	ActionCopyPassword
	ActionCopyUsername
	ActionOpenDetail
	ActionBack
	ActionClose
	ActionTrash
	ActionRestore
	ActionDelete
)

// Row represents a safe display row for a vault item in the list.
// No sensitive secrets are exposed.
type Row struct {
	ID       string
	Title    string
	Subtitle string
	Badge    string
	Conflict bool
	Pending  bool
	Deleted  bool
}

// State represents the full UI state of the omnibox.
type State struct {
	Mode     Mode
	Query    string
	Rows     []Row
	Selected int
	DetailID string
	Status   Status
	Error    string

	// NeedReLogin is true when the current account is LoggedInLocked
	// (token bundle exists but PIN envelope is missing). In this state the
	// legacy master-password unlock path is blocked because it would not
	// create a PIN envelope.
	NeedReLogin bool
}

// NewState returns a State initialised in ModeUnlock with Selected 0.
func NewState() State {
	return State{
		Mode:     ModeUnlock,
		Selected: 0,
	}
}

// Move shifts the selected index by delta, clamping (not wrapping) to
// the valid range [0, len(rows)-1]. If there are no rows, selected stays at 0.
func (s *State) Move(delta int) {
	if len(s.Rows) == 0 {
		s.Selected = 0
		return
	}
	s.Selected += delta
	if s.Selected < 0 {
		s.Selected = 0
	}
	if s.Selected >= len(s.Rows) {
		s.Selected = len(s.Rows) - 1
	}
}

// SetRows replaces the row list and resets the selection if out of bounds.
func (s *State) SetRows(rows []Row) {
	s.Rows = rows
	if len(rows) == 0 {
		s.Selected = 0
	} else if s.Selected >= len(rows) {
		s.Selected = len(rows) - 1
	} else if s.Selected < 0 {
		s.Selected = 0
	}
}

// SelectedRow returns the currently selected row and true, or the zero value
// and false if no rows exist.
func (s *State) SelectedRow() (Row, bool) {
	if len(s.Rows) == 0 || s.Selected < 0 || s.Selected >= len(s.Rows) {
		return Row{}, false
	}
	return s.Rows[s.Selected], true
}

// OpenDetail transitions to ModeDetail, recording the current selected row ID.
// If no row is selected the mode is unchanged.
func (s *State) OpenDetail() {
	if row, ok := s.SelectedRow(); ok {
		s.DetailID = row.ID
		s.Mode = ModeDetail
		s.Selected = 0
	}
}

// Back transitions to ModeSearch from ModeDetail or ModeForm.
// From unlock/keyring modes Back is a no-op (caller can use Escape to quit).
// From ModeSearch, Back is a no-op (caller can use it to close).
func (s *State) Back() {
	switch s.Mode {
	case ModeSearch:
		// No-op: caller can use this event to close the overlay.
	case ModeDetail, ModeForm:
		s.Mode = ModeSearch
		s.DetailID = ""
	case ModeUnlock, ModePINUnlock, ModeKeyringError:
		// Can't go back from unlock/keyring error; caller should ignore.
	default:
		s.Mode = ModeSearch
	}
}

// ModeForAuthStatus returns the appropriate initial mode given the auth status
// and whether an email is configured. It is a pure function suitable for testing.
func ModeForAuthStatus(status session.AuthStatus, hasEmail bool) Mode {
	switch status {
	case session.KeyringUnavailable:
		return ModeKeyringError
	case session.LoggedInUnlockAvailable:
		if hasEmail {
			return ModePINUnlock
		}
		return ModeUnlock
	case session.LoggedInLocked:
		return ModeUnlock
	default:
		// Unauthenticated or any other status.
		return ModeUnlock
	}
}

// SetStatus updates the Status field of the state.
func (s *State) SetStatus(st Status) {
	s.Status = st
}
