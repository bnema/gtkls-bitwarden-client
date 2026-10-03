package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/cache"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// keyedBox is a SecretBox fake that binds ciphertext to its key so wrong-key
// opens fail, and records plaintext buffers it hands out so tests can verify
// they are zeroed.
type keyedBox struct {
	opened [][]byte
}

var errKeyedBoxAuth = errors.New("keyedbox: authentication failed")

func (b *keyedBox) Seal(plaintext, key []byte) ([]byte, error) {
	out := append([]byte(nil), key...)
	return append(out, plaintext...), nil
}

func (b *keyedBox) Open(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < len(key) || !bytes.Equal(ciphertext[:len(key)], key) {
		return nil, errKeyedBoxAuth
	}
	plain := append([]byte(nil), ciphertext[len(key):]...)
	b.opened = append(b.opened, plain)
	return plain, nil
}

type errOutbox struct{ fakeOutbox }

func (o *errOutbox) Load(context.Context, []byte) ([]coresync.OutboxMutation, error) {
	return nil, errors.New("outbox unavailable")
}

var (
	testVCKey  = []byte("test-cache-key-32-bytes-long!!!!")
	testVCSalt = []byte("0123456789abcdef")
)

func testVCData() decryptedCacheSnapshot {
	return decryptedCacheSnapshot{
		Salt:    testVCSalt,
		Items:   []vault.Item{{ID: "i1", Name: "One", Type: vault.ItemTypeLogin}},
		Folders: []vault.Folder{{ID: "f1", Name: "Folder"}},
		Outbox:  []coresync.OutboxMutation{{ID: "m1", Kind: coresync.MutationCreate, ItemID: "i1"}},
		Conflicts: []coresync.Conflict{
			{ID: "c1", ItemID: "i1", MutationID: "m1", Reason: coresync.ConflictBothModified},
		},
	}
}

func TestVaultCacheSealOpenRoundTrip(t *testing.T) {
	store := &fakeCache{}
	vc := vaultCache{store: store, box: &keyedBox{}}

	require.NoError(t, vc.Save(context.Background(), testVCKey, "acct", testVCData()))
	require.Equal(t, 1, store.saveCalled)
	require.Equal(t, cache.Version, store.data.Version)
	require.Equal(t, "acct", store.data.AccountHash)
	require.Equal(t, testVCSalt, store.data.CacheKeySalt)

	got, err := vc.Open(context.Background(), testVCKey)
	require.NoError(t, err)
	want := testVCData()
	require.Equal(t, want, got)
}

func TestVaultCacheOpenWrongKeyFails(t *testing.T) {
	box := &keyedBox{}
	vc := vaultCache{store: &fakeCache{}, box: box}
	require.NoError(t, vc.Save(context.Background(), testVCKey, "acct", testVCData()))

	got, err := vc.Open(context.Background(), []byte("another-key-another-key-another!"))
	require.ErrorIs(t, err, errKeyedBoxAuth)
	require.Contains(t, err.Error(), "cache decrypt")
	require.Empty(t, got.Items)
}

func TestVaultCacheOpenMissingOrEmptyCache(t *testing.T) {
	tests := []struct {
		name  string
		store *fakeCache
	}{
		{"not exist", &fakeCache{loadErr: os.ErrNotExist}},
		{"empty snapshot", &fakeCache{data: &cache.Snapshot{}}},
		{"nil data", &fakeCache{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc := vaultCache{store: tt.store, box: &keyedBox{}}
			got, err := vc.Open(context.Background(), testVCKey)
			require.NoError(t, err)
			require.Empty(t, got.Items)
			require.Empty(t, got.Folders)
			require.Empty(t, got.Outbox)
			require.Empty(t, got.Conflicts)
			require.Empty(t, got.Salt)
		})
	}
}

func TestVaultCacheOpenErrorsAndUnavailable(t *testing.T) {
	ctx := context.Background()

	t.Run("load error", func(t *testing.T) {
		vc := vaultCache{store: &fakeCache{loadErr: errors.New("boom")}, box: &keyedBox{}}
		_, err := vc.Open(ctx, testVCKey)
		require.ErrorContains(t, err, "cache load")
	})
	t.Run("invalid snapshot", func(t *testing.T) {
		vc := vaultCache{store: &fakeCache{data: &cache.Snapshot{Version: 99, AccountHash: "a", VaultCiphertext: []byte("x")}}, box: &keyedBox{}}
		_, err := vc.Open(ctx, testVCKey)
		require.ErrorIs(t, err, cache.ErrInvalidVersion)
	})
	t.Run("empty key", func(t *testing.T) {
		vc := vaultCache{store: &fakeCache{loadErr: errors.New("must not load")}, box: &keyedBox{}}
		got, err := vc.Open(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, got.Items)
	})
	t.Run("no store or box still merges standalone outbox", func(t *testing.T) {
		ob := &fakeOutbox{loadData: []coresync.OutboxMutation{{ID: "m1"}, {ID: "m1"}, {ID: "m2"}}}
		vc := vaultCache{outbox: ob}
		got, err := vc.Open(ctx, testVCKey)
		require.NoError(t, err)
		require.Len(t, got.Outbox, 2)
		require.False(t, vc.Available())
	})
	t.Run("save unavailable", func(t *testing.T) {
		vc := vaultCache{}
		require.ErrorIs(t, vc.Save(ctx, testVCKey, "a", testVCData()), errCacheUnavailable)
	})
}

func TestVaultCacheOpenMergesAndDedupesOutbox(t *testing.T) {
	store := &fakeCache{}
	ob := &fakeOutbox{loadData: []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationDelete}, // duplicate of snapshot m1: snapshot copy wins
		{ID: "m2", Kind: coresync.MutationUpdate},
		{ID: "m2", Kind: coresync.MutationUpdate},
	}}
	vc := vaultCache{store: store, box: &keyedBox{}, outbox: ob}
	require.NoError(t, vc.Save(context.Background(), testVCKey, "acct", testVCData()))

	got, err := vc.Open(context.Background(), testVCKey)
	require.NoError(t, err)
	require.Len(t, got.Outbox, 2)
	require.Equal(t, "m1", got.Outbox[0].ID)
	require.Equal(t, coresync.MutationCreate, got.Outbox[0].Kind)
	require.Equal(t, "m2", got.Outbox[1].ID)
}

func TestVaultCacheOutboxStoreSurvivesItemCacheMissingAndLoadFailure(t *testing.T) {
	ob := &fakeOutbox{loadData: []coresync.OutboxMutation{{ID: "m9"}}}
	vc := vaultCache{store: &fakeCache{loadErr: os.ErrNotExist}, box: &keyedBox{}, outbox: ob}
	got, err := vc.Open(context.Background(), testVCKey)
	require.NoError(t, err)
	require.Len(t, got.Outbox, 1)

	// A failing outbox store is ignored; snapshot outbox is still returned.
	store := &fakeCache{}
	vc = vaultCache{store: store, box: &keyedBox{}, outbox: &errOutbox{}}
	require.NoError(t, vc.Save(context.Background(), testVCKey, "acct", testVCData()))
	got, err = vc.Open(context.Background(), testVCKey)
	require.NoError(t, err)
	require.Len(t, got.Outbox, 1)
	require.Equal(t, "m1", got.Outbox[0].ID)
}

func TestVaultCacheSaveOutbox(t *testing.T) {
	ob := &fakeOutbox{}
	vc := vaultCache{outbox: ob}
	require.NoError(t, vc.SaveOutbox(context.Background(), testVCKey, []coresync.OutboxMutation{{ID: "m1"}}))
	require.Equal(t, 1, ob.saveCalled)
	require.Equal(t, testVCKey, ob.saveKey)

	require.NoError(t, vaultCache{}.SaveOutbox(context.Background(), testVCKey, nil))
}

func TestVaultCacheSaveSaltResolution(t *testing.T) {
	ctx := context.Background()

	t.Run("reuses persisted salt when data has none", func(t *testing.T) {
		store := &fakeCache{data: &cache.Snapshot{CacheKeySalt: testVCSalt}}
		vc := vaultCache{store: store, box: &keyedBox{}}
		data := testVCData()
		data.Salt = nil
		require.NoError(t, vc.Save(ctx, testVCKey, "acct", data))
		require.Equal(t, testVCSalt, store.data.CacheKeySalt)
	})
	t.Run("no salt anywhere", func(t *testing.T) {
		store := &fakeCache{data: &cache.Snapshot{}}
		vc := vaultCache{store: store, box: &keyedBox{}}
		data := testVCData()
		data.Salt = nil
		require.ErrorIs(t, vc.Save(ctx, testVCKey, "acct", data), errNoCacheSalt)
		require.Equal(t, 0, store.saveCalled)
	})
	t.Run("explicit salt wins over persisted", func(t *testing.T) {
		store := &fakeCache{data: &cache.Snapshot{CacheKeySalt: []byte("persisted-salt!!")}}
		vc := vaultCache{store: store, box: &keyedBox{}}
		require.NoError(t, vc.Save(ctx, testVCKey, "acct", testVCData()))
		require.Equal(t, testVCSalt, store.data.CacheKeySalt)
	})
}

func TestVaultCacheOpenWithPassword(t *testing.T) {
	ctx := context.Background()

	t.Run("no cache yields fresh salt and matching key", func(t *testing.T) {
		vc := vaultCache{store: &fakeCache{loadErr: os.ErrNotExist}, box: &keyedBox{}}
		key, data, loaded, err := vc.OpenWithPassword(ctx, "pw")
		require.NoError(t, err)
		require.False(t, loaded)
		require.Len(t, data.Salt, cacheSaltSize)
		require.Equal(t, deriveCacheKey("pw", data.Salt), key)
		require.Empty(t, data.Items)
	})
	t.Run("nil store yields fresh salt", func(t *testing.T) {
		key, data, loaded, err := vaultCache{}.OpenWithPassword(ctx, "pw")
		require.NoError(t, err)
		require.False(t, loaded)
		require.Equal(t, deriveCacheKey("pw", data.Salt), key)
	})
	t.Run("prefers persisted salt and decrypts", func(t *testing.T) {
		store := &fakeCache{}
		ob := &fakeOutbox{loadData: []coresync.OutboxMutation{{ID: "m1"}, {ID: "m3"}}}
		vc := vaultCache{store: store, box: &keyedBox{}, outbox: ob}
		pwKey := deriveCacheKey("pw", testVCSalt)
		require.NoError(t, vc.Save(ctx, pwKey, "acct", testVCData()))

		key, data, loaded, err := vc.OpenWithPassword(ctx, "pw")
		require.NoError(t, err)
		require.True(t, loaded)
		require.Equal(t, pwKey, key)
		require.Equal(t, testVCSalt, data.Salt)
		require.Len(t, data.Items, 1)
		require.Len(t, data.Conflicts, 1)
		require.Len(t, data.Outbox, 2) // m1 deduped, m3 merged
	})
	t.Run("wrong password fails and returns no key", func(t *testing.T) {
		vc := vaultCache{store: &fakeCache{}, box: &keyedBox{}}
		require.NoError(t, vc.Save(ctx, deriveCacheKey("pw", testVCSalt), "acct", testVCData()))

		key, data, loaded, err := vc.OpenWithPassword(ctx, "wrong")
		require.ErrorIs(t, err, errKeyedBoxAuth)
		require.False(t, loaded)
		require.Nil(t, key)
		require.Empty(t, data.Items)
	})
	t.Run("secretbox missing with existing snapshot errors", func(t *testing.T) {
		store := &fakeCache{}
		require.NoError(t, vaultCache{store: store, box: &keyedBox{}}.Save(ctx, testVCKey, "acct", testVCData()))
		_, _, loaded, err := vaultCache{store: store}.OpenWithPassword(ctx, "pw")
		require.ErrorContains(t, err, "secretbox unavailable")
		require.False(t, loaded)
	})
}

func TestVaultCacheZeroesPlaintextBuffers(t *testing.T) {
	box := &keyedBox{}
	vc := vaultCache{store: &fakeCache{}, box: box}
	require.NoError(t, vc.Save(context.Background(), testVCKey, "acct", testVCData()))

	_, err := vc.Open(context.Background(), testVCKey)
	require.NoError(t, err)
	require.Len(t, box.opened, 1)
	require.Equal(t, make([]byte, len(box.opened[0])), box.opened[0], "decrypted plaintext must be zeroed")

	// Decode failure path: valid ciphertext, malformed plaintext.
	bad, err := box.Seal([]byte("not json"), testVCKey)
	require.NoError(t, err)
	vc = vaultCache{store: &fakeCache{data: &cache.Snapshot{Version: cache.Version, AccountHash: "a", VaultCiphertext: bad}}, box: box}
	_, err = vc.Open(context.Background(), testVCKey)
	require.ErrorContains(t, err, "cache decode")
	last := box.opened[len(box.opened)-1]
	require.Equal(t, make([]byte, len(last)), last)
}
