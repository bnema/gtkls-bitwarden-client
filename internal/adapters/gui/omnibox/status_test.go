package omnibox

import (
	"testing"

	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
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
	require.Equal(t, "Vault synced", st.Text)
	require.False(t, st.Syncing)
}

func TestStatusFromEvent_SyncFailed(t *testing.T) {
	evt := in.Event{Kind: in.SyncFailed, Message: "network error"}
	st := StatusFromEvent(evt)
	require.Equal(t, "Network unavailable", st.Text)
	require.False(t, st.Syncing)
	require.Equal(t, "Network unavailable", st.Error)
}

func TestStatusFromEvent_SyncFailed_RawBackendRegression(t *testing.T) {
	evt := in.Event{Kind: in.SyncFailed, Message: "remote sync failed: bitwarden: decryption failed op=crypto.DecryptCipher code=decryption_failed message=failed to decrypt cipher field"}
	st := StatusFromEvent(evt)
	require.Equal(t, "Vault could not be decrypted", st.Text)
	require.False(t, st.Syncing)
	require.Equal(t, "Vault could not be decrypted", st.Error)
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
	require.Equal(t, "Cache loaded — checking sync…", st.Text)
	require.True(t, st.Offline)
	require.True(t, st.Syncing)
}

func TestStatusFromEvent_IndexReady(t *testing.T) {
	evt := in.Event{Kind: in.IndexReady}
	st := StatusFromEvent(evt)
	require.Equal(t, "Search ready", st.Text)
	require.True(t, st.Offline)
	require.False(t, st.Syncing)
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
	evt := in.Event{Kind: in.EventKind("unknown")}
	st := StatusFromEvent(evt)
	require.Empty(t, st.Text)
	require.False(t, st.Syncing)
	require.False(t, st.Offline)
}

func TestReadyStatus(t *testing.T) {
	t.Run("empty clears unlocking state", func(t *testing.T) {
		st := ReadyStatus(0)
		require.Equal(t, "Vault ready — 0 items", st.Text)
		require.False(t, st.Syncing)
		require.Zero(t, st.ItemCount)
	})
	t.Run("one item", func(t *testing.T) {
		st := ReadyStatus(1)
		require.Equal(t, "Vault ready — 1 item", st.Text)
		require.False(t, st.Syncing)
		require.Equal(t, 1, st.ItemCount)
	})
	t.Run("many items", func(t *testing.T) {
		st := ReadyStatus(2)
		require.Equal(t, "Vault ready — 2 items", st.Text)
		require.False(t, st.Syncing)
		require.Equal(t, 2, st.ItemCount)
	})
}

func TestEmptyRowsTextDoesNotEchoQuery(t *testing.T) {
	require.Equal(t, "No matching items", EmptyRowsText("secret@example.com", Status{}))
	require.Equal(t, "Loading vault…", EmptyRowsText("", Status{Syncing: true}))
	require.Equal(t, "No vault items loaded yet", EmptyRowsText("", Status{}))
}

func TestShouldRefreshRowsOnEvent(t *testing.T) {
	require.True(t, ShouldRefreshRowsOnEvent(in.IndexReady))
	require.True(t, ShouldRefreshRowsOnEvent(in.SyncUpdated))
	require.False(t, ShouldRefreshRowsOnEvent(in.SyncChecking))
	require.False(t, ShouldRefreshRowsOnEvent(in.SyncFailed))
}

func TestRefreshRowsDelayForEvent(t *testing.T) {
	require.Equal(t, syncUpdatedRefreshDelay, refreshRowsDelayForEvent(in.SyncUpdated))
	require.Zero(t, refreshRowsDelayForEvent(in.IndexReady))
	require.Zero(t, refreshRowsDelayForEvent(in.SyncFailed))
}
