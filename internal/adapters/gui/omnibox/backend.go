package omnibox

import (
	"context"
	"time"

	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

// searchLimit is the maximum number of rows requested for a search query.
const searchLimit = 50

// Backend is the slice of in.AppService the omnibox work functions use.
// in.AppService satisfies it; tests use a small fake.
type Backend interface {
	Search(ctx context.Context, query string, limit int) ([]vault.ScoredItem, error)
	Items(ctx context.Context) ([]vault.Item, error)
	Conflicts(ctx context.Context) ([]coresync.Conflict, error)
	ConflictDetail(ctx context.Context, conflictID string) (coresync.ConflictDetail, error)
	Get(ctx context.Context, id string) (vault.Item, error)
	Create(ctx context.Context, item vault.Item) (vault.Item, error)
	Update(ctx context.Context, id string, item vault.Item) (vault.Item, error)
	Trash(ctx context.Context, id string) error
	Restore(ctx context.Context, id string) (vault.Item, error)
	Delete(ctx context.Context, id string) error
	ResolveConflict(ctx context.Context, conflictID string, resolution coresync.ConflictResolution) error
	SyncNow(ctx context.Context) error
}

// ErrorReporter receives errors that the work functions handle but that the
// user should not see verbatim (they are logged by the view). A nil reporter
// is allowed.
type ErrorReporter func(operation string, err error)

func (r ErrorReporter) report(operation string, err error) {
	if r != nil && err != nil {
		r(operation, err)
	}
}

// RowsRequest identifies one row load. Seq is assigned by the Controller; only
// the result of the most recently issued request is applied.
type RowsRequest struct {
	Seq   uint64
	Query string
	// KeepStatus leaves the status bar untouched when the rows are applied, so a
	// status explaining a preceding failure stays visible.
	KeepStatus bool
}

// RowsResult is the outcome of FetchRows.
type RowsResult struct {
	Request   RowsRequest
	Rows      []Row
	ItemCount int
	Err       error
}

// FetchRows loads the rows for req: all items for an empty query, scored search
// results otherwise. Conflicts are merged in as placeholder rows; failing to
// load them is reported but does not fail the load.
func FetchRows(ctx context.Context, b Backend, req RowsRequest, report ErrorReporter) RowsResult {
	res := RowsResult{Request: req}
	if req.Query == "" {
		items, err := b.Items(ctx)
		if err != nil {
			report.report("load_items", err)
			res.Err = err
			return res
		}
		conflicts, err := b.Conflicts(ctx)
		report.report("load_conflicts", err)
		res.Rows = RowsWithConflictPlaceholders(RowsFromItems(items), conflicts)
		res.ItemCount = len(items)
		return res
	}
	scored, err := b.Search(ctx, req.Query, searchLimit)
	if err != nil {
		report.report("search", err)
		res.Err = err
		return res
	}
	conflicts, err := b.Conflicts(ctx)
	report.report("search_conflicts", err)
	res.Rows = RowsWithConflictPlaceholders(RowsFromScored(scored), conflicts)
	res.ItemCount = len(scored)
	return res
}

// CopyRequest describes a copy-from-row action.
type CopyRequest struct {
	Row        Row
	Action     Action
	TTL        time.Duration
	CloseAfter bool
}

// CopyResult is the outcome of FetchCopy. Text is the safe status text to show.
type CopyResult struct {
	Text       string
	Failed     bool
	CloseAfter bool
}

// FetchCopy loads the row's item and copies the requested secret to the
// clipboard.
func FetchCopy(ctx context.Context, b Backend, clipboard out.Clipboard, req CopyRequest, report ErrorReporter) CopyResult {
	item, err := b.Get(ctx, req.Row.ID)
	if err != nil {
		report.report("copy_primary_load_item", err)
		return CopyResult{Text: genericOperationError, Failed: true}
	}
	text, err := copyPrimaryAction(ctx, clipboard, item, req.Action, req.TTL)
	if err != nil {
		report.report("copy_primary_action", err)
		return CopyResult{Text: primaryActionErrorStatus(req.Action, err), Failed: true}
	}
	return CopyResult{Text: text, CloseAfter: req.CloseAfter}
}

// DetailResult is the outcome of FetchDetail.
type DetailResult struct {
	Detail Detail
	// Item, when non-nil, replaces the controller's current item (the target of
	// Edit). A conflict placeholder resets it to the zero item.
	Item   *vault.Item
	Failed bool
}

// FetchDetail loads the detail for a row. For conflicted rows it prefers the
// conflict detail, falls back to the plain item, and finally to a conflict-only
// placeholder so the conflict can still be resolved when nothing else loads.
func FetchDetail(ctx context.Context, b Backend, row Row, report ErrorReporter) DetailResult {
	if row.ConflictID != "" {
		conflictDetail, err := b.ConflictDetail(ctx, row.ConflictID)
		if err == nil {
			res := DetailResult{Detail: DetailFromConflictDetail(conflictDetail)}
			if conflictDetail.LocalItem != nil {
				item := *conflictDetail.LocalItem
				res.Item = &item
			}
			return res
		}
		report.report("load_conflict_detail", err)
	}

	item, err := b.Get(ctx, row.ID)
	if err != nil {
		if row.ConflictID != "" {
			return DetailResult{
				Item: &vault.Item{},
				Detail: Detail{
					ID:           row.ID,
					Title:        row.Title,
					Type:         "Conflict",
					Conflict:     true,
					ConflictID:   row.ConflictID,
					ConflictOnly: true,
				},
			}
		}
		report.report("load_detail", err)
		return DetailResult{Failed: true}
	}
	return DetailResult{Detail: DetailFromItem(item), Item: &item}
}

// MutationKind is a lifecycle change applied to an item from its detail view.
type MutationKind int

const (
	MutationTrash MutationKind = iota
	MutationRestore
	MutationDelete
)

func (k MutationKind) operation() string {
	switch k {
	case MutationRestore:
		return "restore"
	case MutationDelete:
		return "delete"
	default:
		return "trash"
	}
}

// MutationRequest describes one lifecycle change.
type MutationRequest struct {
	Kind MutationKind
	ID   string
}

// MutationResult is the outcome of RunMutation.
type MutationResult struct {
	Request MutationRequest
	Failed  bool
}

// RunMutation applies a trash/restore/delete.
func RunMutation(ctx context.Context, b Backend, req MutationRequest, report ErrorReporter) MutationResult {
	var err error
	switch req.Kind {
	case MutationRestore:
		_, err = b.Restore(ctx, req.ID)
	case MutationDelete:
		err = b.Delete(ctx, req.ID)
	default:
		err = b.Trash(ctx, req.ID)
	}
	if err != nil {
		report.report(req.Kind.operation(), err)
		return MutationResult{Request: req, Failed: true}
	}
	return MutationResult{Request: req}
}

// ResolveRequest describes one conflict resolution.
type ResolveRequest struct {
	ConflictID string
	Resolution coresync.ConflictResolution
}

// ResolveOutcome distinguishes the steps of resolve-then-sync.
type ResolveOutcome int

const (
	// ResolveSucceeded means the conflict was resolved and the follow-up sync
	// succeeded.
	ResolveSucceeded ResolveOutcome = iota
	// ResolveFailed means the conflict was not resolved; nothing changed.
	ResolveFailed
	// ResolveSyncFailed means the conflict was resolved locally but the
	// follow-up sync failed, so the result is not yet on the server.
	ResolveSyncFailed
)

// ResolveResult is the outcome of ResolveAndSync.
type ResolveResult struct {
	Request ResolveRequest
	Outcome ResolveOutcome
}

// ResolveAndSync resolves a conflict and then triggers a sync to push the
// result. The sync is skipped when resolving fails.
func ResolveAndSync(ctx context.Context, b Backend, req ResolveRequest, report ErrorReporter) ResolveResult {
	if err := b.ResolveConflict(ctx, req.ConflictID, req.Resolution); err != nil {
		report.report("resolve_conflict", err)
		return ResolveResult{Request: req, Outcome: ResolveFailed}
	}
	if err := b.SyncNow(ctx); err != nil {
		report.report("sync_after_conflict_resolve", err)
		return ResolveResult{Request: req, Outcome: ResolveSyncFailed}
	}
	return ResolveResult{Request: req, Outcome: ResolveSucceeded}
}

// SaveRequest describes one form save. FormID ties the outcome back to the form
// session that produced it.
type SaveRequest struct {
	FormID uint64
	Update bool
	ID     string
	Item   vault.Item
}

// SaveResult is the outcome of SaveForm.
type SaveResult struct {
	Request SaveRequest
	Item    vault.Item
	Failed  bool
}

// SaveForm creates or updates the item described by req.
func SaveForm(ctx context.Context, b Backend, req SaveRequest, report ErrorReporter) SaveResult {
	var (
		item      vault.Item
		err       error
		operation = "create"
	)
	if req.Update {
		operation = "update"
		item, err = b.Update(ctx, req.ID, req.Item)
	} else {
		item, err = b.Create(ctx, req.Item)
	}
	if err != nil {
		report.report(operation, err)
		return SaveResult{Request: req, Failed: true}
	}
	return SaveResult{Request: req, Item: item}
}
