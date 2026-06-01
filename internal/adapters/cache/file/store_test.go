package file

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/cache"
)

func TestStore_Save_CreatesFileWithMode0600(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "cache.json")
	store := NewStore(p)

	snap := cache.Snapshot{
		Version:          1,
		AccountHash:      "testhash",
		LastRevision:     "rev1",
		SavedAt:          time.Now().UTC().Truncate(time.Second),
		VaultCiphertext:  []byte("encrypted-vault-data"),
		OutboxCiphertext: []byte("encrypted-outbox-data"),
	}

	err := store.Save(context.Background(), snap)
	require.NoError(t, err)

	// File exists
	info, err := os.Stat(p)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0600), info.Mode().Perm(), "file mode should be 0600")

	// Parent dir exists
	parentInfo, err := os.Stat(filepath.Dir(p))
	require.NoError(t, err)
	require.True(t, parentInfo.IsDir())
}

func TestStore_Load_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "snap.json")
	store := NewStore(p)

	savedAt := time.Now().UTC().Truncate(time.Second)
	original := cache.Snapshot{
		Version:          1,
		AccountHash:      "acc001",
		LastRevision:     "rev2",
		SavedAt:          savedAt,
		VaultCiphertext:  []byte("vault-cipher"),
		OutboxCiphertext: []byte("outbox-cipher"),
	}

	err := store.Save(context.Background(), original)
	require.NoError(t, err)

	loaded, err := store.Load(context.Background())
	require.NoError(t, err)
	require.Equal(t, original.Version, loaded.Version)
	require.Equal(t, original.AccountHash, loaded.AccountHash)
	require.Equal(t, original.LastRevision, loaded.LastRevision)
	require.True(t, original.SavedAt.Equal(loaded.SavedAt), "SavedAt should round-trip")
	require.Equal(t, original.VaultCiphertext, loaded.VaultCiphertext)
	require.Equal(t, original.OutboxCiphertext, loaded.OutboxCiphertext)
}

func TestStore_Clear_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cache.json")
	store := NewStore(p)

	// Save and then clear
	snap := cache.Snapshot{
		Version:          1,
		AccountHash:      "hash",
		VaultCiphertext:  []byte("data"),
		OutboxCiphertext: []byte("out"),
	}
	err := store.Save(context.Background(), snap)
	require.NoError(t, err)
	require.FileExists(t, p)

	err = store.Clear(context.Background())
	require.NoError(t, err)
	require.NoFileExists(t, p)
}

func TestStore_Clear_MissingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nonexistent.json")
	store := NewStore(p)

	err := store.Clear(context.Background())
	require.NoError(t, err, "clearing a missing file should not error")
}

func TestStore_Load_MissingReturnsErrNotExist(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "missing.json")
	store := NewStore(p)

	_, err := store.Load(context.Background())
	require.True(t, errors.Is(err, fs.ErrNotExist), "should return os.ErrNotExist for missing file")
}

func TestStore_Path(t *testing.T) {
	p := "/some/path/cache.json"
	store := NewStore(p)
	require.Equal(t, p, store.Path())
}
