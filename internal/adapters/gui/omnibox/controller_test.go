package omnibox

import (
	"errors"
	"testing"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
	"github.com/stretchr/testify/require"
)

func searchController() *Controller {
	c := NewController()
	c.State.Mode = ModeSearch
	return c
}

// only returns the single effect of type T, failing if there is not exactly one.
func only[T Effect](t *testing.T, effects []Effect) T {
	t.Helper()
	var found []T
	for _, e := range effects {
		if v, ok := e.(T); ok {
			found = append(found, v)
		}
	}
	require.Len(t, found, 1)
	return found[0]
}

func has[T Effect](effects []Effect) bool {
	for _, e := range effects {
		if _, ok := e.(T); ok {
			return true
		}
	}
	return false
}

func rowsFor(req RowsRequest, titles ...string) RowsResult {
	rows := make([]Row, len(titles))
	for i, title := range titles {
		rows[i] = Row{ID: title, Title: title, Type: string(vault.ItemTypeLogin)}
	}
	return RowsResult{Request: req, Rows: rows, ItemCount: len(rows)}
}

func TestController_StaleSearchResultIsDropped(t *testing.T) {
	c := searchController()

	first := only[EffectFetchRows](t, c.Search("a")).Request
	second := only[EffectFetchRows](t, c.Search("ab")).Request
	require.Greater(t, second.Seq, first.Seq, "every search gets a new sequence number")

	// The newer query finishes first.
	require.NotEmpty(t, c.ApplyRows(rowsFor(second, "ab-result")))
	require.Equal(t, "ab", c.State.Query)
	require.Equal(t, "ab-result", c.State.Rows[0].Title)

	// The older one completes late and must not overwrite it.
	require.Empty(t, c.ApplyRows(rowsFor(first, "a-result")))
	require.Equal(t, "ab", c.State.Query)
	require.Equal(t, "ab-result", c.State.Rows[0].Title)
}

func TestController_EverySearchIsIssuedWhileOneIsInFlight(t *testing.T) {
	// Previously a search arriving during another was silently dropped by a
	// TryLock. Each call must now produce its own fetch.
	c := searchController()
	for _, q := range []string{"a", "ab", "abc"} {
		require.True(t, has[EffectFetchRows](c.Search(q)), q)
	}
}

func TestController_LateFirstResultOfOlderQueryAfterNewerPending(t *testing.T) {
	c := searchController()
	first := only[EffectFetchRows](t, c.Search("a")).Request
	only[EffectFetchRows](t, c.Search("ab"))

	// Newer still in flight; the older result is already obsolete.
	require.Empty(t, c.ApplyRows(rowsFor(first, "a-result")))
	require.Empty(t, c.State.Rows)
}

func TestController_ApplyRows(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		err        error
		category   itemCategory
		prepare    func(c *Controller)
		check      func(t *testing.T, c *Controller, effects []Effect)
		itemCount  int
		resultRows []Row
	}{
		{
			name:       "list all shows ready status",
			resultRows: []Row{{ID: "1", Type: "login"}, {ID: "2", Type: "card"}},
			itemCount:  2,
			check: func(t *testing.T, c *Controller, effects []Effect) {
				require.Len(t, c.State.Rows, 2)
				require.Equal(t, "Vault ready — 2 items", c.State.Status.Text)
				require.True(t, has[EffectRenderRows](effects))
				require.True(t, has[EffectRenderStatus](effects))
			},
		},
		{
			name:       "list all keeps conflict status",
			resultRows: []Row{{ID: "1", Type: "login"}},
			itemCount:  1,
			prepare:    func(c *Controller) { c.State.Status = Status{Text: "Conflict detected", ConflictCount: 1} },
			check: func(t *testing.T, c *Controller, _ []Effect) {
				require.Equal(t, "Conflict detected", c.State.Status.Text)
				require.Equal(t, 1, c.State.Status.ItemCount)
			},
		},
		{
			name:       "search results leave the status alone",
			query:      "x",
			resultRows: []Row{{ID: "1", Type: "login"}},
			itemCount:  1,
			prepare:    func(c *Controller) { c.State.Status = Status{Text: "Vault synced"} },
			check: func(t *testing.T, c *Controller, effects []Effect) {
				require.Equal(t, "Vault synced", c.State.Status.Text)
				require.False(t, has[EffectRenderStatus](effects))
				require.Equal(t, "x", c.State.Query)
			},
		},
		{
			name:       "category filter keeps conflict placeholders",
			category:   categoryCard,
			resultRows: []Row{{ID: "1", Type: "login"}, {ID: "2", Type: "card"}, {ID: "3", Conflict: true, ConflictID: "c"}},
			check: func(t *testing.T, c *Controller, _ []Effect) {
				require.Len(t, c.State.Rows, 2)
				require.Equal(t, "2", c.State.Rows[0].ID)
				require.Equal(t, "3", c.State.Rows[1].ID)
			},
		},
		{
			name: "list all failure sets the error and keeps rows",
			err:  errors.New("x"),
			prepare: func(c *Controller) {
				c.State.Rows = []Row{{ID: "old"}}
			},
			check: func(t *testing.T, c *Controller, effects []Effect) {
				require.Equal(t, genericOperationError, c.State.Error)
				require.Equal(t, "old", c.State.Rows[0].ID)
				require.True(t, has[EffectRender](effects))
			},
		},
		{
			name:  "search failure sets the status and keeps rows",
			query: "x",
			err:   errors.New("x"),
			prepare: func(c *Controller) {
				c.State.Rows = []Row{{ID: "old"}}
			},
			check: func(t *testing.T, c *Controller, effects []Effect) {
				require.Equal(t, genericSearchError, c.State.Status.Text)
				require.Equal(t, genericSearchError, c.State.Status.Error)
				require.Equal(t, "old", c.State.Rows[0].ID)
				require.True(t, has[EffectRenderStatus](effects))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := searchController()
			c.Category = tt.category
			if tt.prepare != nil {
				tt.prepare(c)
			}
			req := only[EffectFetchRows](t, c.Search(tt.query)).Request
			effects := c.ApplyRows(RowsResult{Request: req, Rows: tt.resultRows, ItemCount: tt.itemCount, Err: tt.err})
			tt.check(t, c, effects)
		})
	}
}

func TestController_SearchOnlyInSearchMode(t *testing.T) {
	c := NewController()
	c.State.Mode = ModeDetail
	require.Empty(t, c.Search("x"))
	require.Empty(t, c.QueryChanged("x"))
	require.Empty(t, c.Refresh("x"))
}

func TestController_QueryChangedDebounces(t *testing.T) {
	c := searchController()
	e := only[EffectScheduleSearch](t, c.QueryChanged("abc"))
	require.Equal(t, "abc", e.Query)
	require.Equal(t, searchDebounce, e.Delay)
}

func TestController_EnterSearchLoadsAllItems(t *testing.T) {
	c := NewController()
	c.State.Error = "stale"
	effects := c.EnterSearch()

	require.Equal(t, ModeSearch, c.State.Mode)
	require.Empty(t, c.State.Error)
	require.Equal(t, "", only[EffectFetchRows](t, effects).Request.Query)
	require.True(t, has[EffectRender](effects))
	require.True(t, has[EffectFocusSearch](effects))
	require.False(t, only[EffectSetSyncSuspended](t, effects).Suspended)
}

func TestController_HandleEvent(t *testing.T) {
	tests := []struct {
		name         string
		mode         Mode
		evt          in.Event
		query        string
		wantStatus   string
		wantFetch    bool
		wantSchedule time.Duration
	}{
		{name: "index ready refreshes immediately", mode: ModeSearch, evt: in.Event{Kind: in.IndexReady}, wantStatus: "Search ready", wantFetch: true},
		{name: "conflict refreshes immediately", mode: ModeSearch, evt: in.Event{Kind: in.ConflictDetected, Count: 2}, wantStatus: "Conflict detected", wantFetch: true},
		{name: "sync updated refreshes after settle delay", mode: ModeSearch, evt: in.Event{Kind: in.SyncUpdated}, wantStatus: "Vault synced", wantSchedule: syncUpdatedRefreshDelay},
		{name: "refresh uses the typed query", mode: ModeSearch, evt: in.Event{Kind: in.IndexReady}, query: "git", wantStatus: "Search ready", wantFetch: true},
		{name: "mutation pending refreshes the list", mode: ModeSearch, evt: in.Event{Kind: in.MutationPending, Count: 1}, wantStatus: "Saving…", wantFetch: true},
		{name: "sync checking only sets status", mode: ModeSearch, evt: in.Event{Kind: in.SyncChecking}, wantStatus: "Checking for updates…"},
		{name: "no refresh outside search mode", mode: ModeForm, evt: in.Event{Kind: in.IndexReady}, wantStatus: "Search ready"},
		{name: "no delayed refresh outside search mode", mode: ModeDetail, evt: in.Event{Kind: in.SyncUpdated}, wantStatus: "Vault synced"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewController()
			c.State.Mode = tt.mode
			effects := c.HandleEvent(tt.evt, tt.query)

			require.Equal(t, tt.wantStatus, c.State.Status.Text)
			require.True(t, has[EffectRenderStatus](effects))
			require.True(t, has[EffectCancelRowsRefresh](effects), "a new event cancels any pending delayed refresh")
			if tt.wantFetch {
				require.Equal(t, tt.query, only[EffectFetchRows](t, effects).Request.Query)
			} else {
				require.False(t, has[EffectFetchRows](effects))
			}
			if tt.wantSchedule > 0 {
				require.Equal(t, tt.wantSchedule, only[EffectScheduleRowsRefresh](t, effects).Delay)
			} else {
				require.False(t, has[EffectScheduleRowsRefresh](effects))
			}
		})
	}
}

func TestController_DelayedRefresh(t *testing.T) {
	t.Run("fires when nothing happened since", func(t *testing.T) {
		c := searchController()
		sched := only[EffectScheduleRowsRefresh](t, c.HandleEvent(in.Event{Kind: in.SyncUpdated}, ""))
		effects := c.RefreshTimerFired(sched.Token, "typed")
		require.Equal(t, "typed", only[EffectFetchRows](t, effects).Request.Query)
	})
	t.Run("a newer event invalidates it", func(t *testing.T) {
		c := searchController()
		sched := only[EffectScheduleRowsRefresh](t, c.HandleEvent(in.Event{Kind: in.SyncUpdated}, ""))
		c.HandleEvent(in.Event{Kind: in.SyncChecking}, "")
		require.Empty(t, c.RefreshTimerFired(sched.Token, ""))
	})
	t.Run("leaving search mode invalidates it", func(t *testing.T) {
		c := searchController()
		sched := only[EffectScheduleRowsRefresh](t, c.HandleEvent(in.Event{Kind: in.SyncUpdated}, ""))
		c.State.Mode = ModeDetail
		require.Empty(t, c.RefreshTimerFired(sched.Token, ""))
	})
	t.Run("result of the refresh is subject to last-query-wins", func(t *testing.T) {
		c := searchController()
		sched := only[EffectScheduleRowsRefresh](t, c.HandleEvent(in.Event{Kind: in.SyncUpdated}, ""))
		refresh := only[EffectFetchRows](t, c.RefreshTimerFired(sched.Token, "")).Request
		typed := only[EffectFetchRows](t, c.Search("abc")).Request
		require.Empty(t, c.ApplyRows(rowsFor(refresh, "all")))
		require.NotEmpty(t, c.ApplyRows(rowsFor(typed, "abc")))
	})
}

func TestController_SetCategory(t *testing.T) {
	t.Run("in search mode reloads the list", func(t *testing.T) {
		c := searchController()
		effects := c.SetCategory(categoryCard, "q", nil)
		require.Equal(t, categoryCard, c.Category)
		require.Equal(t, "q", only[EffectFetchRows](t, effects).Request.Query)
		require.True(t, has[EffectRenderTabs](effects))
	})
	t.Run("in form mode restarts the add form for the type", func(t *testing.T) {
		c := NewController()
		c.State.Mode = ModeForm
		effects := c.SetCategory(categoryIdentity, "", nil)
		session := only[EffectShowForm](t, effects).Session
		require.Equal(t, vault.ItemTypeIdentity, session.Item.Type)
		require.Same(t, session, c.Form)
	})
}

func TestController_StartQuickAdd(t *testing.T) {
	t.Run("category All starts a login prefilled with site and password", func(t *testing.T) {
		c := searchController()
		effects := c.StartQuickAdd(" example.com ", func() (string, error) { return "gen-pw", nil })
		session := only[EffectShowForm](t, effects).Session

		require.Equal(t, categoryLogin, c.Category)
		require.Equal(t, ModeForm, c.State.Mode)
		require.Equal(t, vault.ItemTypeLogin, session.Item.Type)
		require.Equal(t, "example.com", session.Value(FieldURI))
		require.Equal(t, "gen-pw", session.Value(FieldPass))
		require.False(t, session.IsUpdate())
		require.True(t, only[EffectSetSyncSuspended](t, effects).Suspended, "sync pauses while the form is open")
	})
	t.Run("generator failure still opens the form and reports in status", func(t *testing.T) {
		c := searchController()
		effects := c.StartQuickAdd("", func() (string, error) { return "partial", errors.New("no character classes") })
		session := only[EffectShowForm](t, effects).Session
		require.Empty(t, session.Value(FieldPass))
		require.Equal(t, "no character classes", c.State.Status.Text)
		require.Equal(t, "no character classes", c.State.Status.Error)
	})
	t.Run("non-login types skip the generator", func(t *testing.T) {
		c := searchController()
		c.Category = categoryCard
		called := false
		effects := c.StartQuickAdd("site", func() (string, error) { called = true; return "x", nil })
		require.False(t, called)
		require.Equal(t, vault.ItemTypeCard, only[EffectShowForm](t, effects).Session.Item.Type)
	})
	t.Run("ctrl+n forces login", func(t *testing.T) {
		c := searchController()
		c.Category = categoryCard
		effects := c.StartQuickAddLogin("", nil)
		require.Equal(t, vault.ItemTypeLogin, only[EffectShowForm](t, effects).Session.Item.Type)
		require.Equal(t, categoryLogin, c.Category)
	})
}

func TestController_Activate(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.CloseAfterCopy = true

	t.Run("no rows is a no-op", func(t *testing.T) {
		require.Empty(t, searchController().Activate(false, false, cfg))
	})
	t.Run("enter copies the password", func(t *testing.T) {
		c := searchController()
		c.State.SetRows([]Row{{ID: "i1", Type: "login"}})
		req := only[EffectCopyRow](t, c.Activate(false, false, cfg)).Request
		require.Equal(t, ActionCopyPassword, req.Action)
		require.Equal(t, "i1", req.Row.ID)
		require.True(t, req.CloseAfter)
		require.Equal(t, ModeSearch, c.State.Mode)
	})
	t.Run("alt+enter copies the username", func(t *testing.T) {
		c := searchController()
		c.State.SetRows([]Row{{ID: "i1", Type: "login"}})
		require.Equal(t, ActionCopyUsername, only[EffectCopyRow](t, c.Activate(false, true, cfg)).Request.Action)
	})
	t.Run("ctrl+enter opens the detail", func(t *testing.T) {
		c := searchController()
		c.State.SetRows([]Row{{ID: "i1", Type: "login"}})
		effects := c.Activate(true, false, cfg)
		require.Equal(t, ModeDetail, c.State.Mode)
		require.Equal(t, "i1", c.State.DetailID)
		require.Equal(t, "i1", only[EffectLoadDetail](t, effects).Row.ID)
		require.True(t, has[EffectRender](effects))
	})
	t.Run("conflict placeholder opens the detail", func(t *testing.T) {
		c := searchController()
		c.State.SetRows([]Row{{ID: "i1", Conflict: true, ConflictID: "c1"}})
		require.True(t, has[EffectLoadDetail](c.Activate(false, false, cfg)))
		require.Equal(t, ModeDetail, c.State.Mode)
	})
	t.Run("nil config copies the password without closing", func(t *testing.T) {
		c := searchController()
		c.State.SetRows([]Row{{ID: "i1", Type: "login"}})
		req := only[EffectCopyRow](t, c.Activate(false, false, nil)).Request
		require.Equal(t, ActionCopyPassword, req.Action)
		require.False(t, req.CloseAfter)
	})
}

func TestController_ApplyCopy(t *testing.T) {
	tests := []struct {
		name      string
		res       CopyResult
		wantText  string
		wantError string
		wantClose bool
	}{
		{name: "success", res: CopyResult{Text: "Password copied"}, wantText: "Password copied"},
		{name: "success closes after delay", res: CopyResult{Text: "Password copied", CloseAfter: true}, wantText: "Password copied", wantClose: true},
		{name: "failure never closes", res: CopyResult{Text: "Clipboard unavailable", Failed: true, CloseAfter: true}, wantText: "Clipboard unavailable", wantError: "Clipboard unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := searchController()
			effects := c.ApplyCopy(tt.res)
			require.Equal(t, tt.wantText, c.State.Status.Text)
			require.Equal(t, tt.wantError, c.State.Status.Error)
			require.Equal(t, tt.wantClose, has[EffectClose](effects))
			if tt.wantClose {
				require.Equal(t, closeAfterCopyDelay, only[EffectClose](t, effects).Delay)
			}
		})
	}
}

func detailController(rowID string) *Controller {
	c := NewController()
	c.State.Mode = ModeDetail
	c.State.DetailID = rowID
	return c
}

func TestController_ApplyDetail(t *testing.T) {
	t.Run("renders and remembers the item for edit", func(t *testing.T) {
		c := detailController("i1")
		item := vault.Item{ID: "i1", Name: "N", Type: vault.ItemTypeLogin}
		effects := c.ApplyDetail(DetailResult{RowID: "i1", Detail: Detail{ID: "i1"}, Item: &item})
		require.Equal(t, "i1", only[EffectRenderDetail](t, effects).Detail.ID)
		require.Equal(t, item, c.Item)
	})
	t.Run("conflict placeholder resets the item", func(t *testing.T) {
		c := detailController("i1")
		c.Item = vault.Item{ID: "stale"}
		c.ApplyDetail(DetailResult{RowID: "i1", Detail: Detail{ConflictOnly: true}, Item: &vault.Item{}})
		require.Equal(t, vault.Item{}, c.Item)
	})
	t.Run("failure sets the error", func(t *testing.T) {
		c := detailController("i1")
		effects := c.ApplyDetail(DetailResult{RowID: "i1", Failed: true})
		require.Equal(t, genericOperationError, c.State.Error)
		require.True(t, has[EffectRender](effects))
		require.False(t, has[EffectRenderDetail](effects))
	})
	t.Run("late result after leaving detail is dropped", func(t *testing.T) {
		c := searchController()
		require.Empty(t, c.ApplyDetail(DetailResult{RowID: "i1", Detail: Detail{ID: "i1"}}))
	})
	t.Run("slow result for row A cannot overwrite row B", func(t *testing.T) {
		c := searchController()
		c.State.SetRows([]Row{{ID: "A", Type: "login"}, {ID: "B", Type: "login"}})
		cfg := config.Default()
		cfg.Actions.DefaultPrimaryAction = config.ActionOpenDetail

		c.Activate(false, false, cfg) // opens A
		require.Equal(t, "A", c.State.DetailID)
		c.Back() // user goes back and opens B before A's load finishes
		c.State.SetRows([]Row{{ID: "B", Type: "login"}})
		c.State.Selected = 0
		c.Activate(false, false, cfg)
		require.Equal(t, "B", c.State.DetailID)

		itemB := vault.Item{ID: "B", Name: "Bee"}
		require.NotEmpty(t, c.ApplyDetail(DetailResult{RowID: "B", Detail: Detail{ID: "B"}, Item: &itemB}))

		itemA := vault.Item{ID: "A", Name: "Ay"}
		require.Empty(t, c.ApplyDetail(DetailResult{RowID: "A", Detail: Detail{ID: "A"}, Item: &itemA}))
		require.Equal(t, itemB, c.Item, "edit target stays B")
	})
	t.Run("slow failure for row A does not flag row B", func(t *testing.T) {
		c := detailController("B")
		require.Empty(t, c.ApplyDetail(DetailResult{RowID: "A", Failed: true}))
		require.Empty(t, c.State.Error)
	})
}

func TestFetchDetail_CarriesRowID(t *testing.T) {
	for _, tt := range []struct {
		name    string
		row     Row
		backend *fakeBackend
	}{
		{"plain success", Row{ID: "i1"}, &fakeBackend{got: map[string]vault.Item{"i1": {ID: "i1"}}}},
		{"plain failure", Row{ID: "i1"}, &fakeBackend{getErr: errBoom}},
		{"conflict placeholder", Row{ID: "i1", ConflictID: "c"}, &fakeBackend{conflictDetailErr: errBoom, getErr: errBoom}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, "i1", FetchDetail(t.Context(), tt.backend, tt.row, nil).RowID)
		})
	}
}

func TestController_Mutations(t *testing.T) {
	t.Run("success closes the detail through Back and reloads the list", func(t *testing.T) {
		c := detailController("i1")
		req := only[EffectMutateItem](t, c.Mutate(MutationTrash, "i1")).Request
		effects := c.ApplyMutation(MutationResult{Request: req}, "typed")
		require.Equal(t, ModeSearch, c.State.Mode)
		require.True(t, has[EffectRender](effects))
		require.False(t, only[EffectSetSyncSuspended](t, effects).Suspended, "Back reapplies sync suspension")
		require.Equal(t, "typed", only[EffectFetchRows](t, effects).Request.Query)
	})
	t.Run("success also drops any open form session", func(t *testing.T) {
		c := detailController("i1")
		c.Form = newFormSession(1, vault.Item{Type: vault.ItemTypeLogin})
		c.ApplyMutation(MutationResult{Request: MutationRequest{Kind: MutationDelete, ID: "i1"}}, "")
		require.Nil(t, c.Form)
	})
	t.Run("failure stays and shows the error in the status line", func(t *testing.T) {
		c := detailController("i1")
		effects := c.ApplyMutation(MutationResult{Request: MutationRequest{ID: "i1"}, Failed: true}, "")
		require.Equal(t, ModeDetail, c.State.Mode)
		require.Equal(t, genericOperationError, c.State.Status.Text)
		require.Equal(t, genericOperationError, c.State.Status.Error)
		require.True(t, has[EffectRenderStatus](effects))
	})
	t.Run("stale success after moving to another item does not navigate", func(t *testing.T) {
		c := detailController("B")
		effects := c.ApplyMutation(MutationResult{Request: MutationRequest{Kind: MutationTrash, ID: "A"}}, "")
		require.Equal(t, ModeDetail, c.State.Mode)
		require.Equal(t, "B", c.State.DetailID)
		require.False(t, has[EffectRender](effects))
		require.False(t, has[EffectSetSyncSuspended](effects))
	})
	t.Run("stale success after leaving detail does not pop the current mode", func(t *testing.T) {
		c := NewController()
		c.State.Mode = ModeForm
		c.Form = newFormSession(1, vault.Item{Type: vault.ItemTypeLogin})
		effects := c.ApplyMutation(MutationResult{Request: MutationRequest{ID: "A"}}, "")
		require.Equal(t, ModeForm, c.State.Mode)
		require.NotNil(t, c.Form)
		require.Empty(t, effects, "no list reload outside search mode")
	})
	t.Run("stale success in search mode only reloads the list", func(t *testing.T) {
		c := searchController()
		effects := c.ApplyMutation(MutationResult{Request: MutationRequest{ID: "A"}}, "q")
		require.Equal(t, ModeSearch, c.State.Mode)
		require.Equal(t, "q", only[EffectFetchRows](t, effects).Request.Query)
	})
}

func TestController_EditOpensCurrentItem(t *testing.T) {
	c := NewController()
	c.State.Mode = ModeDetail
	c.Item = vault.Item{ID: "i1", Name: "Mine", Type: vault.ItemTypeSecureNote, Notes: "n"}
	session := only[EffectShowForm](t, c.Edit()).Session
	require.True(t, session.IsUpdate())
	require.Equal(t, "Mine", session.Value(FieldName))
	require.Equal(t, ModeForm, c.State.Mode)
}

func TestController_ResolveConflict(t *testing.T) {
	t.Run("empty conflict id is ignored", func(t *testing.T) {
		require.Empty(t, NewController().ResolveConflict("", coresync.ResolutionKeepLocal))
	})
	t.Run("start shows progress and requests the work", func(t *testing.T) {
		c := NewController()
		effects := c.ResolveConflict("c1", coresync.ResolutionKeepRemote)
		require.Equal(t, "Resolving conflict…", c.State.Status.Text)
		require.True(t, c.State.Status.Syncing)
		req := only[EffectResolveConflict](t, effects).Request
		require.Equal(t, ResolveRequest{ConflictID: "c1", Resolution: coresync.ResolutionKeepRemote}, req)
	})

	tests := []struct {
		name         string
		outcome      ResolveOutcome
		wantMode     Mode
		wantStatus   string
		wantError    bool
		wantFetch    bool
		wantKeepStat bool
	}{
		{name: "full success returns to a refreshed list", outcome: ResolveSucceeded, wantMode: ModeSearch, wantStatus: "Resolving conflict…", wantFetch: true},
		{name: "resolve failure stays in detail, generic error", outcome: ResolveFailed, wantMode: ModeDetail, wantStatus: genericOperationError, wantError: true},
		{name: "sync failure after resolve returns to list and says so", outcome: ResolveSyncFailed, wantMode: ModeSearch, wantStatus: resolveSyncFailedText, wantError: true, wantFetch: true, wantKeepStat: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewController()
			c.State.Mode = ModeDetail
			c.State.DetailID = "i1"
			c.ResolveConflict("c1", coresync.ResolutionKeepLocal)
			effects := c.ApplyResolve(ResolveResult{Request: ResolveRequest{ConflictID: "c1"}, Outcome: tt.outcome}, "typed")

			require.Equal(t, tt.wantMode, c.State.Mode)
			require.Equal(t, tt.wantStatus, c.State.Status.Text)
			require.Equal(t, tt.wantError, c.State.Status.Error != "")
			require.Equal(t, tt.wantFetch, has[EffectFetchRows](effects))
			if tt.wantFetch {
				req := only[EffectFetchRows](t, effects).Request
				require.Equal(t, "typed", req.Query)
				require.Equal(t, tt.wantKeepStat, req.KeepStatus)
				require.Empty(t, c.State.DetailID)
			} else {
				require.Equal(t, "i1", c.State.DetailID)
			}
		})
	}

	t.Run("sync failure text survives the list reload", func(t *testing.T) {
		c := NewController()
		c.State.Mode = ModeDetail
		effects := c.ApplyResolve(ResolveResult{Outcome: ResolveSyncFailed}, "")
		req := only[EffectFetchRows](t, effects).Request
		c.ApplyRows(RowsResult{Request: req, Rows: []Row{{ID: "1"}}, ItemCount: 1})
		require.Equal(t, resolveSyncFailedText, c.State.Status.Text)
	})
	t.Run("success list reload replaces the progress status", func(t *testing.T) {
		c := NewController()
		c.State.Mode = ModeDetail
		c.ResolveConflict("c1", coresync.ResolutionKeepLocal)
		effects := c.ApplyResolve(ResolveResult{Outcome: ResolveSucceeded}, "")
		req := only[EffectFetchRows](t, effects).Request
		c.ApplyRows(RowsResult{Request: req, Rows: []Row{{ID: "1"}}, ItemCount: 1})
		require.Equal(t, "Vault ready — 1 item", c.State.Status.Text)
	})
}

func TestController_Back(t *testing.T) {
	c := NewController()
	c.State.Mode = ModeForm
	c.Form = newFormSession(1, vault.Item{Type: vault.ItemTypeLogin})
	effects := c.Back()
	require.Equal(t, ModeSearch, c.State.Mode)
	require.Nil(t, c.Form, "leaving the form drops the session")
	require.False(t, only[EffectSetSyncSuspended](t, effects).Suspended)
	require.True(t, has[EffectRender](effects))
}
