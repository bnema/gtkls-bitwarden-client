package omnibox

import (
	"testing"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/stretchr/testify/require"
)

// openFormController returns a controller in form mode on a fresh session.
func openFormController(t *testing.T, item vault.Item) (*Controller, *FormSession) {
	t.Helper()
	c := searchController()
	return c, only[EffectShowForm](t, c.OpenForm(item)).Session
}

func TestController_SubmitForm_ValidationError(t *testing.T) {
	c, s := openFormController(t, vault.Item{Type: vault.ItemTypeCard})
	effects := c.SubmitForm(s, map[FieldKey]string{FieldName: " "})

	require.Len(t, effects, 1, "no save is started")
	e := only[EffectFormError](t, effects)
	require.Same(t, s, e.Session)
	require.Equal(t, "item name is required", e.Text)
	require.False(t, s.Saving, "the form stays editable")
}

func TestController_SubmitForm_SavePerType(t *testing.T) {
	tests := []struct {
		name       string
		item       vault.Item
		values     map[FieldKey]string
		wantUpdate bool
		wantID     string
		check      func(t *testing.T, got vault.Item)
	}{
		{
			name:   "new login creates",
			item:   vault.Item{Type: vault.ItemTypeLogin, Login: &vault.Login{}},
			values: map[FieldKey]string{FieldURI: "example.com", FieldUser: "me", FieldPass: "pw"},
			check:  func(t *testing.T, got vault.Item) { require.Equal(t, "example.com (me)", got.Name) },
		},
		{
			name:       "existing login updates by id",
			item:       vault.Item{ID: "i1", Name: "Old", Type: vault.ItemTypeLogin, Login: &vault.Login{Password: "old"}},
			values:     map[FieldKey]string{FieldName: "New", FieldPass: "new", FieldUser: "u"},
			wantUpdate: true, wantID: "i1",
			check: func(t *testing.T, got vault.Item) {
				require.Equal(t, "New", got.Name)
				require.Equal(t, "new", got.Login.Password)
			},
		},
		{
			name:   "new note creates",
			item:   vault.Item{Type: vault.ItemTypeSecureNote},
			values: map[FieldKey]string{FieldName: "N", FieldNotes: "body"},
			check:  func(t *testing.T, got vault.Item) { require.Equal(t, "body", got.SecureNote.Text) },
		},
		{
			name:       "existing card updates",
			item:       vault.Item{ID: "c1", Name: "Visa", Type: vault.ItemTypeCard, Card: &vault.Card{Number: "4111"}},
			values:     map[FieldKey]string{FieldName: "Visa", FieldNumber: "5500"},
			wantUpdate: true, wantID: "c1",
			check: func(t *testing.T, got vault.Item) { require.Equal(t, "5500", got.Card.Number) },
		},
		{
			name:   "new identity creates",
			item:   vault.Item{Type: vault.ItemTypeIdentity},
			values: map[FieldKey]string{FieldName: "Me", FieldFirstName: "A"},
			check:  func(t *testing.T, got vault.Item) { require.Equal(t, "A", got.Identity.FirstName) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, s := openFormController(t, tt.item)
			effects := c.SubmitForm(s, tt.values)

			require.True(t, s.Saving)
			require.Equal(t, "", only[EffectFormError](t, effects).Text, "previous error is cleared")
			require.True(t, only[EffectFormSaving](t, effects).Saving)
			req := only[EffectSaveForm](t, effects).Request
			require.Equal(t, s.ID, req.FormID)
			require.Equal(t, tt.wantUpdate, req.Update)
			require.Equal(t, tt.wantID, req.ID)
			require.Equal(t, tt.item.Type, req.Item.Type)
			tt.check(t, req.Item)
		})
	}
}

func TestController_SubmitForm_IgnoredWhileSavingOrStale(t *testing.T) {
	c, s := openFormController(t, vault.Item{Type: vault.ItemTypeSecureNote})
	values := map[FieldKey]string{FieldName: "N"}
	require.NotEmpty(t, c.SubmitForm(s, values))
	require.Empty(t, c.SubmitForm(s, values), "second submit while saving is ignored")

	_, old := openFormController(t, vault.Item{Type: vault.ItemTypeSecureNote})
	require.Empty(t, c.SubmitForm(old, values), "a session that is not the open form is ignored")
	require.Empty(t, c.SubmitForm(nil, values))
}

func TestController_ApplySave(t *testing.T) {
	saved := vault.Item{ID: "new", Name: "Saved Name", Type: vault.ItemTypeSecureNote}

	t.Run("failure re-enables the form with a generic error", func(t *testing.T) {
		c, s := openFormController(t, vault.Item{Type: vault.ItemTypeSecureNote})
		c.SubmitForm(s, map[FieldKey]string{FieldName: "N"})
		effects := c.ApplySave(SaveResult{Request: SaveRequest{FormID: s.ID}, Failed: true}, "")

		require.False(t, s.Saving)
		require.False(t, only[EffectFormSaving](t, effects).Saving)
		require.Equal(t, genericSaveError, only[EffectFormError](t, effects).Text)
		require.Equal(t, ModeForm, c.State.Mode, "stays on the form so typed values survive")
		// A retry is possible.
		require.NotEmpty(t, c.SubmitForm(s, map[FieldKey]string{FieldName: "N"}))
	})

	t.Run("success reports the item and returns to the refreshed list", func(t *testing.T) {
		c, s := openFormController(t, vault.Item{Type: vault.ItemTypeSecureNote})
		c.State.Error = "stale"
		c.State.DetailID = "d"
		c.SubmitForm(s, map[FieldKey]string{FieldName: "N"})
		effects := c.ApplySave(SaveResult{Request: SaveRequest{FormID: s.ID}, Item: saved}, "typed")

		require.Equal(t, ModeSearch, c.State.Mode)
		require.Equal(t, "Saved Saved Name", c.State.Status.Text)
		require.Empty(t, c.State.Error)
		require.Empty(t, c.State.DetailID)
		require.Equal(t, saved, c.Item)
		require.Nil(t, c.Form)
		require.False(t, only[EffectSetSyncSuspended](t, effects).Suspended)
		require.True(t, has[EffectRender](effects))
		require.Equal(t, "typed", only[EffectFetchRows](t, effects).Request.Query)
		require.True(t, has[EffectFocusSearch](effects))
	})

	t.Run("success after the user left the form does not navigate", func(t *testing.T) {
		c, s := openFormController(t, vault.Item{Type: vault.ItemTypeSecureNote})
		c.SubmitForm(s, map[FieldKey]string{FieldName: "N"})
		c.Back() // user leaves while the save is in flight
		require.Equal(t, ModeSearch, c.State.Mode)
		c.State.Mode = ModeDetail // and moves on to something else

		effects := c.ApplySave(SaveResult{Request: SaveRequest{FormID: s.ID}, Item: saved}, "")
		require.Equal(t, ModeDetail, c.State.Mode)
		require.Equal(t, "Saved Saved Name", c.State.Status.Text)
		require.True(t, has[EffectRenderStatus](effects))
		require.False(t, has[EffectFocusSearch](effects))
	})

	t.Run("failure after the form was replaced is dropped", func(t *testing.T) {
		c, s := openFormController(t, vault.Item{Type: vault.ItemTypeSecureNote})
		c.SubmitForm(s, map[FieldKey]string{FieldName: "N"})
		newer := only[EffectShowForm](t, c.OpenForm(vault.Item{Type: vault.ItemTypeCard})).Session

		require.Empty(t, c.ApplySave(SaveResult{Request: SaveRequest{FormID: s.ID}, Failed: true}, ""))
		require.False(t, newer.Saving)
		require.Same(t, newer, c.Form)
	})

	t.Run("success of an older form does not close a newer one", func(t *testing.T) {
		c, s := openFormController(t, vault.Item{Type: vault.ItemTypeSecureNote})
		c.SubmitForm(s, map[FieldKey]string{FieldName: "N"})
		newer := only[EffectShowForm](t, c.OpenForm(vault.Item{Type: vault.ItemTypeCard})).Session

		c.ApplySave(SaveResult{Request: SaveRequest{FormID: s.ID}, Item: saved}, "")
		require.Equal(t, ModeForm, c.State.Mode)
		require.Same(t, newer, c.Form)
	})
}
