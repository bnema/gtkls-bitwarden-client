package omnibox

import (
	"testing"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
	"github.com/stretchr/testify/require"
)

func TestStatusFromEvent_SyncChecking(t *testing.T) {
	evt := in.Event{Kind: in.SyncChecking}
	st := StatusFromEvent(evt)
	require.Equal(t, "Checking for updates…", st.Text)
	require.True(t, st.Syncing)
}

func TestStatusFromEvent_SyncUpdated(t *testing.T) {
	evt := in.Event{Kind: in.SyncUpdated}
	st := StatusFromEvent(evt)
	require.Equal(t, "Vault updated", st.Text)
	require.False(t, st.Syncing)
}

func TestStatusFromEvent_SyncFailed(t *testing.T) {
	evt := in.Event{Kind: in.SyncFailed, Message: "network error"}
	st := StatusFromEvent(evt)
	require.Equal(t, "network error", st.Text)
	require.False(t, st.Syncing)
	require.Equal(t, "network error", st.Error)
}

func TestStatusFromEvent_SyncFailed_EmptyMessage(t *testing.T) {
	evt := in.Event{Kind: in.SyncFailed}
	st := StatusFromEvent(evt)
	require.Equal(t, "Sync failed", st.Text)
	require.False(t, st.Syncing)
	require.Equal(t, "Sync failed", st.Error)
}

func TestStatusFromEvent_MutationPending(t *testing.T) {
	evt := in.Event{Kind: in.MutationPending, Count: 3}
	st := StatusFromEvent(evt)
	require.Equal(t, "Saving…", st.Text)
	require.True(t, st.Syncing)
	require.Equal(t, 3, st.PendingCount)
}

func TestStatusFromEvent_ConflictDetected(t *testing.T) {
	evt := in.Event{Kind: in.ConflictDetected, Count: 2}
	st := StatusFromEvent(evt)
	require.Equal(t, "Conflict detected", st.Text)
	require.False(t, st.Syncing)
	require.Equal(t, 2, st.ConflictCount)
}

func TestStatusFromEvent_CacheLoaded(t *testing.T) {
	evt := in.Event{Kind: in.CacheLoaded}
	st := StatusFromEvent(evt)
	require.Equal(t, "Cache loaded", st.Text)
	require.True(t, st.Offline)
}

func TestStatusFromEvent_Locked(t *testing.T) {
	evt := in.Event{Kind: in.Locked}
	st := StatusFromEvent(evt)
	require.Equal(t, "Locked", st.Text)
	require.True(t, st.Offline)
}

func TestStatusFromEvent_Relocked(t *testing.T) {
	evt := in.Event{Kind: in.Relocked}
	st := StatusFromEvent(evt)
	require.Equal(t, "Relocked", st.Text)
	require.True(t, st.Offline)
}

func TestStatusFromEvent_Unlocking(t *testing.T) {
	evt := in.Event{Kind: in.Unlocking}
	st := StatusFromEvent(evt)
	require.Equal(t, "Unlocking…", st.Text)
	require.True(t, st.Syncing)
}

func TestStatusFromEvent_Default(t *testing.T) {
	evt := in.Event{Kind: in.IndexReady}
	st := StatusFromEvent(evt)
	require.Empty(t, st.Text)
	require.False(t, st.Syncing)
	require.False(t, st.Offline)
}
