package omnibox

import (
	"strings"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
)

const (
	genericOperationError = "Something went wrong"
	genericSearchError    = "Search failed"
	genericSaveError      = "Save failed"

	// resolveSyncFailedText is shown when the conflict was resolved locally but
	// the follow-up sync failed; a failed resolve shows genericOperationError.
	resolveSyncFailedText = "Conflict resolved, but sync failed"

	// searchDebounce is how long typing must pause before a search runs.
	searchDebounce = 150 * time.Millisecond
	// closeAfterCopyDelay lets the clipboard helper take ownership of the
	// copied value before the overlay goes away.
	closeAfterCopyDelay = 200 * time.Millisecond
)

// PasswordGenerator produces a password to prefill new login forms.
type PasswordGenerator func() (string, error)

// Controller is the pure orchestration core of the omnibox. It owns State and
// turns user intents and service outcomes into state changes plus Effects.
//
// A Controller does no I/O and is not safe for concurrent use: the view calls
// it under its own mutex and performs the returned Effects afterwards, in
// order, on the GTK main loop. Methods named Apply* take the outcome of an
// asynchronous work effect.
type Controller struct {
	State State
	// Category is the active item category tab.
	Category itemCategory
	// Item is the item shown in the detail panel, the target of Edit.
	Item vault.Item
	// Form is the open form session, if any.
	Form *FormSession

	// searchSeq numbers row loads; only the newest result is applied so the
	// last query always wins regardless of completion order.
	searchSeq uint64
	// refreshToken invalidates delayed refreshes: every event bumps it.
	refreshToken uint64
	formSeq      uint64
}

// NewController returns a Controller in ModeUnlock showing all categories.
func NewController() *Controller {
	return &Controller{State: NewState(), Category: categoryAll}
}

// SetMode switches mode and keeps background sync suspension in step with it.
func (c *Controller) SetMode(mode Mode) []Effect {
	c.State.Mode = mode
	if mode != ModeForm {
		// Leaving the form abandons its session; a late save outcome then no
		// longer navigates anywhere.
		c.Form = nil
	}
	return []Effect{EffectSetSyncSuspended{Suspended: syncSuspendedForMode(mode)}}
}

// Back steps back one logical mode (see State.Back) and re-renders.
func (c *Controller) Back() []Effect {
	c.State.Back()
	effects := c.SetMode(c.State.Mode)
	return append(effects, EffectRender{})
}

// EnterSearch enters search mode after a successful unlock and loads all items.
func (c *Controller) EnterSearch() []Effect {
	c.State.Error = ""
	effects := c.SetMode(ModeSearch)
	effects = append(effects, EffectRender{}, EffectFocusSearch{})
	return append(effects, c.fetchRows("")...)
}

// ShowSearch switches to the search tab and reloads rows for query.
func (c *Controller) ShowSearch(query string) []Effect {
	effects := c.SetMode(ModeSearch)
	effects = append(effects, EffectRender{}, EffectFocusSearch{})
	return append(effects, c.fetchRows(query)...)
}

// QueryChanged schedules a debounced search for the text now in the entry.
func (c *Controller) QueryChanged(query string) []Effect {
	if c.State.Mode != ModeSearch {
		return nil
	}
	return []Effect{EffectScheduleSearch{Delay: searchDebounce, Query: query}}
}

// Search loads the rows for query (typically when the debounce fires). An empty
// query lists all items. Any result still in flight for an earlier query is
// discarded when it arrives, so the last query always wins. It only applies in
// search mode.
func (c *Controller) Search(query string) []Effect {
	return c.refresh(query)
}

// Refresh reloads the visible list for query after cache, index, or sync
// changes. It only applies in search mode.
func (c *Controller) Refresh(query string) []Effect {
	return c.refresh(query)
}

func (c *Controller) refresh(query string) []Effect {
	if c.State.Mode != ModeSearch {
		return nil
	}
	return c.fetchRows(query)
}

func (c *Controller) fetchRows(query string) []Effect {
	return c.fetchRowsKeepingStatus(query, false)
}

func (c *Controller) fetchRowsKeepingStatus(query string, keepStatus bool) []Effect {
	c.searchSeq++
	return []Effect{EffectFetchRows{Request: RowsRequest{Seq: c.searchSeq, Query: query, KeepStatus: keepStatus}}}
}

// ApplyRows applies a finished row load unless a newer one has been issued.
func (c *Controller) ApplyRows(res RowsResult) []Effect {
	if res.Request.Seq != c.searchSeq {
		return nil
	}
	listAll := res.Request.Query == ""
	if res.Err != nil {
		if listAll {
			c.State.Error = genericOperationError
			return []Effect{EffectRender{}}
		}
		c.State.SetStatus(errorStatus(genericSearchError))
		return []Effect{EffectRenderStatus{}}
	}
	c.State.Query = res.Request.Query
	c.State.SetRows(FilterRowsByCategory(res.Rows, c.Category))
	effects := []Effect{EffectRenderRows{}}
	if listAll && !res.Request.KeepStatus {
		c.State.SetStatus(StatusAfterRowsLoaded(c.State.Status, res.ItemCount))
		effects = append(effects, EffectRenderStatus{})
	}
	return effects
}

// FilterRowsByCategory keeps the rows matching the category. Conflict
// placeholders have no type and are always kept so they stay resolvable.
func FilterRowsByCategory(rows []Row, category itemCategory) []Row {
	if category == categoryAll {
		return rows
	}
	want := string(categoryItemType(category))
	filtered := make([]Row, 0, len(rows))
	for _, row := range rows {
		if row.Type == want || (row.Conflict && row.ConflictID != "" && row.Type == "") {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

// HandleEvent applies a service event: it updates the status and, when the
// event means the list may be stale, reloads it for query (immediately or after
// the event's settle delay). A newer event cancels an earlier delayed refresh.
func (c *Controller) HandleEvent(evt in.Event, query string) []Effect {
	c.refreshToken++
	c.State.SetStatus(StatusFromEvent(evt))
	effects := []Effect{EffectCancelRowsRefresh{}, EffectRenderStatus{}}
	if !ShouldRefreshRowsOnEvent(evt.Kind) || c.State.Mode != ModeSearch {
		return effects
	}
	if delay := refreshRowsDelayForEvent(evt.Kind); delay > 0 {
		return append(effects, EffectScheduleRowsRefresh{Delay: delay, Token: c.refreshToken})
	}
	return append(effects, c.fetchRows(query)...)
}

// RefreshTimerFired runs a delayed refresh scheduled by HandleEvent unless a
// newer event or a mode change made it obsolete.
func (c *Controller) RefreshTimerFired(token uint64, query string) []Effect {
	if token != c.refreshToken {
		return nil
	}
	return c.Refresh(query)
}

// SetCategory selects a category tab. In form mode it restarts the add form for
// the new item type; otherwise it reloads the list.
func (c *Controller) SetCategory(category itemCategory, query string, generate PasswordGenerator) []Effect {
	c.Category = category
	if c.State.Mode == ModeForm {
		return c.StartQuickAdd(query, generate)
	}
	return append([]Effect{EffectRenderTabs{}}, c.refresh(query)...)
}

// StartQuickAddLogin opens the add form on the Login category (Ctrl+N).
func (c *Controller) StartQuickAddLogin(site string, generate PasswordGenerator) []Effect {
	c.Category = categoryLogin
	return c.StartQuickAdd(site, generate)
}

// StartQuickAdd opens a blank add form for the active category (login when the
// category is All). Logins are prefilled with the typed site and a generated
// password; a generation failure is shown in the status bar.
func (c *Controller) StartQuickAdd(site string, generate PasswordGenerator) []Effect {
	if c.Category == categoryAll {
		c.Category = categoryLogin
	}
	itemType := categoryItemType(c.Category)
	password := ""
	if itemType == vault.ItemTypeLogin && generate != nil {
		var err error
		if password, err = generate(); err != nil {
			password = ""
			c.State.SetStatus(errorStatus(err.Error()))
		}
	}
	item := NewQuickAddItem(itemType, strings.TrimSpace(site), password)
	return c.OpenForm(item)
}

// OpenForm opens the form for item (a new item when it has no ID).
func (c *Controller) OpenForm(item vault.Item) []Effect {
	c.formSeq++
	c.Item = item
	effects := c.SetMode(ModeForm)
	c.Form = newFormSession(c.formSeq, item)
	return append(effects, EffectShowForm{Session: c.Form})
}

// Edit opens the current detail item for editing.
func (c *Controller) Edit() []Effect {
	return c.OpenForm(c.Item)
}

// Activate handles Enter in search mode for the selected row: copy the
// password or username, or open the detail panel.
func (c *Controller) Activate(ctrlPressed, altPressed bool, cfg *config.Config) []Effect {
	row, ok := c.State.SelectedRow()
	if !ok {
		return nil
	}
	action := SearchEnterActionForModifiers(row, cfg, ctrlPressed, altPressed)
	switch action {
	case ActionCopyPassword, ActionCopyUsername:
		ttl, closeAfter := SearchCopyOptions(cfg)
		return []Effect{EffectCopyRow{Request: CopyRequest{Row: row, Action: action, TTL: ttl, CloseAfter: closeAfter}}}
	default:
		c.State.OpenDetail()
		if c.State.Mode != ModeDetail || c.State.DetailID == "" {
			return nil
		}
		effects := c.SetMode(ModeDetail)
		return append(effects, EffectLoadDetail{Row: row}, EffectRender{})
	}
}

// ApplyCopy shows the outcome of a copy and closes the overlay after a
// successful copy when configured.
func (c *Controller) ApplyCopy(res CopyResult) []Effect {
	if res.Failed {
		c.State.SetStatus(errorStatus(res.Text))
	} else {
		c.State.SetStatus(Status{Text: res.Text})
	}
	effects := []Effect{EffectRenderStatus{}}
	if !res.Failed && res.CloseAfter {
		effects = append(effects, EffectClose{Delay: closeAfterCopyDelay})
	}
	return effects
}

// ApplyDetail shows a loaded detail. A result is dropped unless the detail
// panel is open for the same row it was requested for, so a slow load for one
// row cannot overwrite the detail or edit target of another.
func (c *Controller) ApplyDetail(res DetailResult) []Effect {
	if !c.detailOpenFor(res.RowID) {
		return nil
	}
	if res.Failed {
		c.State.Error = genericOperationError
		return []Effect{EffectRender{}}
	}
	if res.Item != nil {
		c.Item = *res.Item
	}
	return []Effect{EffectRenderDetail{Detail: res.Detail}}
}

func (c *Controller) detailOpenFor(id string) bool {
	return c.State.Mode == ModeDetail && c.State.DetailID == id
}

// Mutate trashes, restores, or permanently deletes an item from its detail.
func (c *Controller) Mutate(kind MutationKind, id string) []Effect {
	return []Effect{EffectMutateItem{Request: MutationRequest{Kind: kind, ID: id}}}
}

// ApplyMutation applies the outcome of a trash/restore/delete. A failure is
// shown in the status line (the unlock-panel error label is hidden in detail
// mode). On success the detail panel of that item closes through Back, which
// reapplies the mode's sync suspension, and the list is reloaded for query so
// the item's new state shows. If the user already moved on, only the list is
// reloaded.
func (c *Controller) ApplyMutation(res MutationResult, query string) []Effect {
	if res.Failed {
		c.State.SetStatus(errorStatus(genericOperationError))
		return []Effect{EffectRenderStatus{}}
	}
	if !c.detailOpenFor(res.Request.ID) {
		return c.refresh(query)
	}
	effects := c.Back()
	return append(effects, c.fetchRows(query)...)
}

// ResolveConflict starts resolving a conflict: resolve, then sync.
func (c *Controller) ResolveConflict(conflictID string, resolution coresync.ConflictResolution) []Effect {
	if conflictID == "" {
		return nil
	}
	c.State.SetStatus(Status{Text: "Resolving conflict…", Syncing: true})
	return []Effect{
		EffectRenderStatus{},
		EffectResolveConflict{Request: ResolveRequest{ConflictID: conflictID, Resolution: resolution}},
	}
}

// ApplyResolve applies the outcome of resolve-then-sync. A failed resolve
// changed nothing, so the detail panel stays for a retry. When only the
// follow-up sync failed the conflict is already resolved locally: the view
// returns to the refreshed list, and the status says that the sync failed
// (and is not overwritten by the list reload) so the user is not told the
// resolution itself failed.
func (c *Controller) ApplyResolve(res ResolveResult, query string) []Effect {
	if res.Outcome == ResolveFailed {
		c.State.SetStatus(errorStatus(genericOperationError))
		return []Effect{EffectRenderStatus{}}
	}
	keepStatus := false
	if res.Outcome == ResolveSyncFailed {
		c.State.SetStatus(errorStatus(resolveSyncFailedText))
		keepStatus = true
	}
	effects := c.SetMode(ModeSearch)
	c.State.DetailID = ""
	effects = append(effects, EffectRender{})
	if keepStatus {
		return append(effects, c.fetchRowsKeepingStatus(query, true)...)
	}
	return append(effects, c.fetchRows(query)...)
}

// SubmitForm validates the submitted values and starts saving. values maps
// every form field key to its current text. It is ignored while a save is in
// flight or if s is no longer the open form.
func (c *Controller) SubmitForm(s *FormSession, values map[FieldKey]string) []Effect {
	if s == nil || s != c.Form || s.Saving {
		return nil
	}
	item, err := s.Build(values)
	if err != nil {
		return []Effect{EffectFormError{Session: s, Text: err.Error()}}
	}
	s.Saving = true
	return []Effect{
		EffectFormError{Session: s},
		EffectFormSaving{Session: s, Saving: true},
		EffectSaveForm{Request: SaveRequest{FormID: s.ID, Update: s.IsUpdate(), ID: s.Item.ID, Item: item}},
	}
}

// ApplySave applies the outcome of a save. A failure re-enables the form with
// an error. Success reports the saved item and, if the form is still open,
// returns to the refreshed search list.
func (c *Controller) ApplySave(res SaveResult, query string) []Effect {
	s := c.Form
	active := s != nil && s.ID == res.Request.FormID
	if res.Failed {
		if !active {
			return nil
		}
		s.Saving = false
		return []Effect{
			EffectFormSaving{Session: s},
			EffectFormError{Session: s, Text: genericSaveError},
		}
	}
	c.State.Error = ""
	c.State.SetStatus(Status{Text: "Saved " + res.Item.Name})
	if !active {
		// The user already left this form; report the save but do not navigate.
		return append([]Effect{EffectRenderStatus{}}, c.refresh(query)...)
	}
	c.Item = res.Item
	c.State.DetailID = ""
	effects := c.SetMode(ModeSearch)
	effects = append(effects, EffectRender{})
	effects = append(effects, c.refresh(query)...)
	return append(effects, EffectFocusSearch{})
}

func errorStatus(text string) Status {
	return Status{Text: text, Error: text}
}
