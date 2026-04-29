package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/cache/crypto"
	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
)

func TestOutboxStore_SaveThenLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "outbox.json")
	box := crypto.NewBox()
	store := NewOutboxStore(p, box)

	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	mutations := []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "item-1", Payload: []byte(`{"id":"item-1"}`)},
		{ID: "m2", Kind: coresync.MutationUpdate, ItemID: "item-2", Payload: []byte(`{"id":"item-2"}`)},
	}

	err := store.Save(context.Background(), key, mutations)
	require.NoError(t, err)

	// File should exist with mode 0600
	info, err := os.Stat(p)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Load back
	loaded, err := store.Load(context.Background(), key)
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	require.Equal(t, mutations[0].ID, loaded[0].ID)
	require.Equal(t, mutations[1].ID, loaded[1].ID)
	require.Equal(t, mutations[0].Kind, loaded[0].Kind)
	require.Equal(t, mutations[1].Kind, loaded[1].Kind)
	require.Equal(t, mutations[0].Payload, loaded[0].Payload)
	require.Equal(t, mutations[1].Payload, loaded[1].Payload)
}

func TestOutboxStore_SaveEmpty_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "outbox.json")
	box := crypto.NewBox()
	store := NewOutboxStore(p, box)

	key := make([]byte, chacha20poly1305.KeySize)

	// First save something
	err := store.Save(context.Background(), key, []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "item-1"},
	})
	require.NoError(t, err)
	require.FileExists(t, p)

	// Save empty should remove the file
	err = store.Save(context.Background(), key, nil)
	require.NoError(t, err)
	require.NoFileExists(t, p)

	// Also works when file already doesn't exist
	err = store.Save(context.Background(), key, nil)
	require.NoError(t, err)
}

func TestOutboxStore_LoadMissing_ReturnsNilNil(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nonexistent.json")
	box := crypto.NewBox()
	store := NewOutboxStore(p, box)

	key := make([]byte, chacha20poly1305.KeySize)
	loaded, err := store.Load(context.Background(), key)
	require.NoError(t, err)
	require.Nil(t, loaded)
}

func TestOutboxStore_LoadNilBox_WithExistingFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "outbox.json")

	// First save with a real box
	box := crypto.NewBox()
	store := NewOutboxStore(p, box)
	key := make([]byte, chacha20poly1305.KeySize)

	err := store.Save(context.Background(), key, []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "item-1"},
	})
	require.NoError(t, err)
	require.FileExists(t, p)

	// Now load with nil box
	nilStore := NewOutboxStore(p, nil)
	_, err = nilStore.Load(context.Background(), key)
	require.Error(t, err)
	require.Contains(t, err.Error(), "secretbox unavailable")
}

func TestOutboxStore_SaveNilBox_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "outbox.json")
	store := NewOutboxStore(p, nil)

	key := make([]byte, chacha20poly1305.KeySize)
	err := store.Save(context.Background(), key, []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "item-1"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "secretbox unavailable")
}

func TestOutboxStore_Path(t *testing.T) {
	p := "/some/path/outbox.json"
	box := crypto.NewBox()
	store := NewOutboxStore(p, box)
	require.Equal(t, p, store.Path())
}
