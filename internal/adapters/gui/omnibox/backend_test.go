package omnibox

import (
	"context"
	"errors"
	"testing"

	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
	"github.com/stretchr/testify/require"
)

// The real service must satisfy the narrow Backend the work functions use.
var _ Backend = in.AppService(nil)

var errBoom = errors.New("boom")

// fakeBackend is a scriptable Backend that records calls.
type fakeBackend struct {
	items     []vault.Item
	itemsErr  error
	scored    []vault.ScoredItem
	searchErr error
	conflicts []coresync.Conflict
	conflErr  error

	conflictDetail    coresync.ConflictDetail
	conflictDetailErr error
	got               map[string]vault.Item
	getErr            error

	createErr, updateErr, trashErr, restoreErr, deleteErr, resolveErr, syncErr error

	calls []string
	saved vault.Item
}

func (f *fakeBackend) rec(s string) { f.calls = append(f.calls, s) }

func (f *fakeBackend) Search(_ context.Context, query string, limit int) ([]vault.ScoredItem, error) {
	f.rec("search:" + query)
	if limit != searchLimit {
		return nil, errors.New("unexpected limit")
	}
	return f.scored, f.searchErr
}

func (f *fakeBackend) Items(context.Context) ([]vault.Item, error) {
	f.rec("items")
	return f.items, f.itemsErr
}

func (f *fakeBackend) Conflicts(context.Context) ([]coresync.Conflict, error) {
	f.rec("conflicts")
	return f.conflicts, f.conflErr
}

func (f *fakeBackend) ConflictDetail(_ context.Context, id string) (coresync.ConflictDetail, error) {
	f.rec("conflict_detail:" + id)
	return f.conflictDetail, f.conflictDetailErr
}

func (f *fakeBackend) Get(_ context.Context, id string) (vault.Item, error) {
	f.rec("get:" + id)
	if f.getErr != nil {
		return vault.Item{}, f.getErr
	}
	return f.got[id], nil
}

func (f *fakeBackend) Create(_ context.Context, item vault.Item) (vault.Item, error) {
	f.rec("create")
	f.saved = item
	if f.createErr != nil {
		return vault.Item{}, f.createErr
	}
	item.ID = "new-id"
	return item, nil
}

func (f *fakeBackend) Update(_ context.Context, id string, item vault.Item) (vault.Item, error) {
	f.rec("update:" + id)
	f.saved = item
	if f.updateErr != nil {
		return vault.Item{}, f.updateErr
	}
	item.ID = id
	return item, nil
}

func (f *fakeBackend) Trash(_ context.Context, id string) error {
	f.rec("trash:" + id)
	return f.trashErr
}

func (f *fakeBackend) Restore(_ context.Context, id string) (vault.Item, error) {
	f.rec("restore:" + id)
	return vault.Item{ID: id}, f.restoreErr
}

func (f *fakeBackend) Delete(_ context.Context, id string) error {
	f.rec("delete:" + id)
	return f.deleteErr
}

func (f *fakeBackend) ResolveConflict(_ context.Context, id string, _ coresync.ConflictResolution) error {
	f.rec("resolve:" + id)
	return f.resolveErr
}

func (f *fakeBackend) SyncNow(context.Context) error {
	f.rec("sync")
	return f.syncErr
}

type reported struct{ operations []string }

func (r *reported) report(op string, _ error) { r.operations = append(r.operations, op) }

func TestFetchRows(t *testing.T) {
	login := vault.Item{ID: "1", Name: "Alpha", Type: vault.ItemTypeLogin}
	tests := []struct {
		name      string
		query     string
		backend   *fakeBackend
		wantErr   bool
		wantRows  int
		wantCount int
		wantCalls []string
		wantOps   []string
	}{
		{
			name:      "empty query lists all items",
			backend:   &fakeBackend{items: []vault.Item{login}},
			wantRows:  1,
			wantCount: 1,
			wantCalls: []string{"items", "conflicts"},
		},
		{
			name:      "conflict load failure is reported but not fatal",
			backend:   &fakeBackend{items: []vault.Item{login}, conflErr: errBoom},
			wantRows:  1,
			wantCount: 1,
			wantCalls: []string{"items", "conflicts"},
			wantOps:   []string{"load_conflicts"},
		},
		{
			name:      "items failure fails the load",
			backend:   &fakeBackend{itemsErr: errBoom},
			wantErr:   true,
			wantCalls: []string{"items"},
			wantOps:   []string{"load_items"},
		},
		{
			name:    "query runs a scored search and adds conflict placeholders",
			query:   "alp",
			backend: &fakeBackend{scored: []vault.ScoredItem{{Item: login}}, conflicts: []coresync.Conflict{{ID: "c1", ItemID: "gone"}}},
			// one scored row plus one conflict placeholder
			wantRows:  2,
			wantCount: 1,
			wantCalls: []string{"search:alp", "conflicts"},
		},
		{
			name:      "search failure fails the load",
			query:     "alp",
			backend:   &fakeBackend{searchErr: errBoom},
			wantErr:   true,
			wantCalls: []string{"search:alp"},
			wantOps:   []string{"search"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r reported
			res := FetchRows(context.Background(), tt.backend, RowsRequest{Seq: 7, Query: tt.query}, r.report)
			require.Equal(t, uint64(7), res.Request.Seq)
			require.Equal(t, tt.wantErr, res.Err != nil)
			require.Len(t, res.Rows, tt.wantRows)
			require.Equal(t, tt.wantCount, res.ItemCount)
			require.Equal(t, tt.wantCalls, tt.backend.calls)
			require.Equal(t, tt.wantOps, r.operations)
		})
	}
}

func TestFetchRows_NilReporter(t *testing.T) {
	res := FetchRows(context.Background(), &fakeBackend{itemsErr: errBoom}, RowsRequest{}, nil)
	require.Error(t, res.Err)
}

func TestFetchDetail_FallbackChain(t *testing.T) {
	local := vault.Item{ID: "i1", Name: "Local", Type: vault.ItemTypeLogin}
	remote := vault.Item{ID: "i1", Name: "Remote", Type: vault.ItemTypeLogin}
	plainRow := Row{ID: "i1", Title: "Plain"}
	conflictRow := Row{ID: "i1", Title: "Conflicted", ConflictID: "c1"}

	tests := []struct {
		name      string
		row       Row
		backend   *fakeBackend
		check     func(t *testing.T, res DetailResult)
		wantCalls []string
		wantOps   []string
	}{
		{
			name:    "conflict detail wins and its local item becomes the current item",
			row:     conflictRow,
			backend: &fakeBackend{conflictDetail: coresync.ConflictDetail{Conflict: coresync.Conflict{ID: "c1", ItemID: "i1"}, LocalItem: &local, RemoteItem: &remote}},
			check: func(t *testing.T, res DetailResult) {
				require.False(t, res.Failed)
				require.True(t, res.Detail.ConflictOnly)
				require.Equal(t, "c1", res.Detail.ConflictID)
				require.NotNil(t, res.Item)
				require.Equal(t, "Local", res.Item.Name)
			},
			wantCalls: []string{"conflict_detail:c1"},
		},
		{
			name:    "conflict detail without local item leaves the current item alone",
			row:     conflictRow,
			backend: &fakeBackend{conflictDetail: coresync.ConflictDetail{Conflict: coresync.Conflict{ID: "c1"}, RemoteItem: &remote}},
			check: func(t *testing.T, res DetailResult) {
				require.Nil(t, res.Item)
				require.Equal(t, "Remote", res.Detail.Title)
			},
			wantCalls: []string{"conflict_detail:c1"},
		},
		{
			name: "conflict detail failure falls back to the plain item",
			row:  conflictRow,
			backend: &fakeBackend{
				conflictDetailErr: errBoom,
				got:               map[string]vault.Item{"i1": {ID: "i1", Name: "Plain item", Type: vault.ItemTypeLogin, SyncStatus: vault.SyncStatusConflict, ConflictID: "c1"}},
			},
			check: func(t *testing.T, res DetailResult) {
				require.False(t, res.Failed)
				require.Equal(t, "Plain item", res.Detail.Title)
				require.True(t, res.Detail.Conflict)
				require.NotNil(t, res.Item)
			},
			wantCalls: []string{"conflict_detail:c1", "get:i1"},
			wantOps:   []string{"load_conflict_detail"},
		},
		{
			name:    "both failing yields a resolvable conflict-only placeholder",
			row:     conflictRow,
			backend: &fakeBackend{conflictDetailErr: errBoom, getErr: errBoom},
			check: func(t *testing.T, res DetailResult) {
				require.False(t, res.Failed)
				require.True(t, res.Detail.ConflictOnly)
				require.Equal(t, "c1", res.Detail.ConflictID)
				require.Equal(t, "Conflicted", res.Detail.Title)
				require.NotEmpty(t, ConflictResolutionActions(res.Detail))
				// Edit must not target a stale item.
				require.NotNil(t, res.Item)
				require.Equal(t, vault.Item{}, *res.Item)
			},
			wantCalls: []string{"conflict_detail:c1", "get:i1"},
			wantOps:   []string{"load_conflict_detail"},
		},
		{
			name:    "plain row failure is a failed detail",
			row:     plainRow,
			backend: &fakeBackend{getErr: errBoom},
			check: func(t *testing.T, res DetailResult) {
				require.True(t, res.Failed)
				require.Nil(t, res.Item)
			},
			wantCalls: []string{"get:i1"},
			wantOps:   []string{"load_detail"},
		},
		{
			name:    "plain row loads the item",
			row:     plainRow,
			backend: &fakeBackend{got: map[string]vault.Item{"i1": local}},
			check: func(t *testing.T, res DetailResult) {
				require.Equal(t, "Local", res.Detail.Title)
				require.Equal(t, "Local", res.Item.Name)
			},
			wantCalls: []string{"get:i1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r reported
			res := FetchDetail(context.Background(), tt.backend, tt.row, r.report)
			tt.check(t, res)
			require.Equal(t, tt.wantCalls, tt.backend.calls)
			require.Equal(t, tt.wantOps, r.operations)
		})
	}
}

func TestResolveAndSync(t *testing.T) {
	req := ResolveRequest{ConflictID: "c1", Resolution: coresync.ResolutionKeepLocal}
	tests := []struct {
		name      string
		backend   *fakeBackend
		want      ResolveOutcome
		wantCalls []string
		wantOps   []string
	}{
		{name: "resolve then sync", backend: &fakeBackend{}, want: ResolveSucceeded, wantCalls: []string{"resolve:c1", "sync"}},
		{name: "resolve failure skips sync", backend: &fakeBackend{resolveErr: errBoom}, want: ResolveFailed, wantCalls: []string{"resolve:c1"}, wantOps: []string{"resolve_conflict"}},
		{name: "sync failure after resolve is distinct", backend: &fakeBackend{syncErr: errBoom}, want: ResolveSyncFailed, wantCalls: []string{"resolve:c1", "sync"}, wantOps: []string{"sync_after_conflict_resolve"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r reported
			res := ResolveAndSync(context.Background(), tt.backend, req, r.report)
			require.Equal(t, tt.want, res.Outcome)
			require.Equal(t, req, res.Request)
			require.Equal(t, tt.wantCalls, tt.backend.calls)
			require.Equal(t, tt.wantOps, r.operations)
		})
	}
}

func TestRunMutation(t *testing.T) {
	tests := []struct {
		name       string
		kind       MutationKind
		backend    *fakeBackend
		wantCall   string
		wantFailed bool
		wantOp     string
	}{
		{name: "trash", kind: MutationTrash, backend: &fakeBackend{}, wantCall: "trash:x"},
		{name: "restore", kind: MutationRestore, backend: &fakeBackend{}, wantCall: "restore:x"},
		{name: "delete", kind: MutationDelete, backend: &fakeBackend{}, wantCall: "delete:x"},
		{name: "trash failure", kind: MutationTrash, backend: &fakeBackend{trashErr: errBoom}, wantCall: "trash:x", wantFailed: true, wantOp: "trash"},
		{name: "restore failure", kind: MutationRestore, backend: &fakeBackend{restoreErr: errBoom}, wantCall: "restore:x", wantFailed: true, wantOp: "restore"},
		{name: "delete failure", kind: MutationDelete, backend: &fakeBackend{deleteErr: errBoom}, wantCall: "delete:x", wantFailed: true, wantOp: "delete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r reported
			res := RunMutation(context.Background(), tt.backend, MutationRequest{Kind: tt.kind, ID: "x"}, r.report)
			require.Equal(t, tt.wantFailed, res.Failed)
			require.Equal(t, []string{tt.wantCall}, tt.backend.calls)
			if tt.wantOp == "" {
				require.Empty(t, r.operations)
			} else {
				require.Equal(t, []string{tt.wantOp}, r.operations)
			}
		})
	}
}

func TestSaveForm(t *testing.T) {
	item := vault.Item{Name: "N", Type: vault.ItemTypeSecureNote}
	tests := []struct {
		name       string
		req        SaveRequest
		backend    *fakeBackend
		wantCall   string
		wantFailed bool
		wantOp     string
		wantID     string
	}{
		{name: "create", req: SaveRequest{Item: item}, backend: &fakeBackend{}, wantCall: "create", wantID: "new-id"},
		{name: "update", req: SaveRequest{Update: true, ID: "i9", Item: item}, backend: &fakeBackend{}, wantCall: "update:i9", wantID: "i9"},
		{name: "create failure", req: SaveRequest{Item: item}, backend: &fakeBackend{createErr: errBoom}, wantCall: "create", wantFailed: true, wantOp: "create"},
		{name: "update failure", req: SaveRequest{Update: true, ID: "i9", Item: item}, backend: &fakeBackend{updateErr: errBoom}, wantCall: "update:i9", wantFailed: true, wantOp: "update"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r reported
			res := SaveForm(context.Background(), tt.backend, tt.req, r.report)
			require.Equal(t, tt.wantFailed, res.Failed)
			require.Equal(t, []string{tt.wantCall}, tt.backend.calls)
			require.Equal(t, tt.wantID, res.Item.ID)
			if tt.wantOp == "" {
				require.Empty(t, r.operations)
			} else {
				require.Equal(t, []string{tt.wantOp}, r.operations)
			}
		})
	}
}

func TestFetchCopy(t *testing.T) {
	withPassword := vault.Item{ID: "i1", Type: vault.ItemTypeLogin, Login: &vault.Login{Password: "pw"}}
	var r reported

	t.Run("load failure", func(t *testing.T) {
		res := FetchCopy(context.Background(), &fakeBackend{getErr: errBoom}, nil, CopyRequest{Row: Row{ID: "i1"}, Action: ActionCopyPassword}, r.report)
		require.True(t, res.Failed)
		require.Equal(t, genericOperationError, res.Text)
	})
	t.Run("missing clipboard is reported safely", func(t *testing.T) {
		res := FetchCopy(context.Background(), &fakeBackend{got: map[string]vault.Item{"i1": withPassword}}, nil, CopyRequest{Row: Row{ID: "i1"}, Action: ActionCopyPassword}, r.report)
		require.True(t, res.Failed)
		require.Equal(t, "Clipboard unavailable", res.Text)
	})
	t.Run("non-login item", func(t *testing.T) {
		note := vault.Item{ID: "i1", Type: vault.ItemTypeSecureNote}
		res := FetchCopy(context.Background(), &fakeBackend{got: map[string]vault.Item{"i1": note}}, nil, CopyRequest{Row: Row{ID: "i1"}, Action: ActionCopyUsername}, r.report)
		require.True(t, res.Failed)
	})
	require.Equal(t, []string{"copy_primary_load_item", "copy_primary_action", "copy_primary_action"}, r.operations)
}
