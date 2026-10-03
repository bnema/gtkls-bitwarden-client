package omnibox

import "time"

// Effect is a side effect requested by the Controller. The GTK view performs
// effects on the main loop; the Controller never touches widgets, timers, the
// service, or goroutines itself, which keeps all orchestration testable.
//
// Effects come in two flavours: UI effects (render, focus, close, …) and work
// effects (Fetch*, Load*, Mutate*, Resolve*). A work effect carries a request
// that the view runs off the main loop with the matching function from
// backend.go; the outcome is then fed back to the Controller.
type Effect interface {
	isEffect()
}

// EffectRender asks for a full re-render: panel visibility, tabs and status.
type EffectRender struct{}

// EffectRenderTabs asks for the tab/category button styles to be refreshed.
type EffectRenderTabs struct{}

// EffectRenderRows asks for the result list to be rebuilt.
type EffectRenderRows struct{}

// EffectRenderStatus asks for the status footer to be refreshed.
type EffectRenderStatus struct{}

// EffectRenderDetail asks for the detail panel to be rebuilt.
type EffectRenderDetail struct{ Detail Detail }

// EffectFocusSearch moves keyboard focus to the search entry.
type EffectFocusSearch struct{}

// EffectShowForm asks the view to build the form widgets for Session, show
// the form panel, and focus the first field.
type EffectShowForm struct{ Session *FormSession }

// EffectFormError shows (empty text: clears) the form-local error of Session.
type EffectFormError struct {
	Session *FormSession
	Text    string
}

// EffectFormSaving toggles the save button of Session.
type EffectFormSaving struct {
	Session *FormSession
	Saving  bool
}

// EffectSaveForm asks the view to run SaveForm and feed the result back
// through Controller.ApplySave.
type EffectSaveForm struct{ Request SaveRequest }

// EffectSetSyncSuspended toggles background sync suspension on the service.
type EffectSetSyncSuspended struct{ Suspended bool }

// EffectClose asks the view to close the overlay after Delay (0 = now).
type EffectClose struct{ Delay time.Duration }

// EffectScheduleSearch asks the view to call Controller.Search with Query after
// Delay, replacing any previously scheduled search (debounce).
type EffectScheduleSearch struct {
	Delay time.Duration
	Query string
}

// EffectScheduleRowsRefresh asks the view to call Controller.RefreshTimerFired
// with Token and the text currently in the search entry after Delay, replacing
// any previously scheduled refresh.
type EffectScheduleRowsRefresh struct {
	Delay time.Duration
	Token uint64
}

// EffectCancelRowsRefresh cancels a scheduled EffectScheduleRowsRefresh.
type EffectCancelRowsRefresh struct{}

// EffectFetchRows asks the view to run FetchRows and feed the result back
// through Controller.ApplyRows.
type EffectFetchRows struct{ Request RowsRequest }

// EffectCopyRow asks the view to run FetchCopy and feed the result back
// through Controller.ApplyCopy.
type EffectCopyRow struct{ Request CopyRequest }

// EffectLoadDetail asks the view to run FetchDetail and feed the result back
// through Controller.ApplyDetail.
type EffectLoadDetail struct{ Row Row }

// EffectMutateItem asks the view to run RunMutation and feed the result back
// through Controller.ApplyMutation.
type EffectMutateItem struct{ Request MutationRequest }

// EffectResolveConflict asks the view to run ResolveAndSync and feed the
// result back through Controller.ApplyResolve.
type EffectResolveConflict struct{ Request ResolveRequest }

func (EffectRender) isEffect()              {}
func (EffectRenderTabs) isEffect()          {}
func (EffectRenderRows) isEffect()          {}
func (EffectRenderStatus) isEffect()        {}
func (EffectRenderDetail) isEffect()        {}
func (EffectFocusSearch) isEffect()         {}
func (EffectShowForm) isEffect()            {}
func (EffectFormError) isEffect()           {}
func (EffectFormSaving) isEffect()          {}
func (EffectSaveForm) isEffect()            {}
func (EffectScheduleSearch) isEffect()      {}
func (EffectSetSyncSuspended) isEffect()    {}
func (EffectClose) isEffect()               {}
func (EffectScheduleRowsRefresh) isEffect() {}
func (EffectCancelRowsRefresh) isEffect()   {}
func (EffectFetchRows) isEffect()           {}
func (EffectCopyRow) isEffect()             {}
func (EffectLoadDetail) isEffect()          {}
func (EffectMutateItem) isEffect()          {}
func (EffectResolveConflict) isEffect()     {}
