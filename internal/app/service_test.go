package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/cache"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	coreerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	coresync "github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// fakeOutbox implements ports.OutboxStore for testing.
type fakeOutbox struct {
	mu         sync.Mutex
	loadData   []coresync.OutboxMutation
	loadErr    error
	saveData   []coresync.OutboxMutation
	saveKey    []byte
	saveCalled int
}

func (o *fakeOutbox) Load(_ context.Context, key []byte) ([]coresync.OutboxMutation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.loadData, o.loadErr
}

func (o *fakeOutbox) Save(_ context.Context, key []byte, mutations []coresync.OutboxMutation) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.saveCalled++
	o.saveKey = make([]byte, len(key))
	copy(o.saveKey, key)
	o.saveData = make([]coresync.OutboxMutation, len(mutations))
	copy(o.saveData, mutations)
	return nil
}

// ---------------------------------------------------------------------------
// Fake implementations for testing.
// ---------------------------------------------------------------------------

type fakeRemote struct {
	mu          sync.Mutex
	loginCalled bool
	lockCalled  bool
	revisionRev string
	revisionErr error
	syncStarted atomic.Bool

	syncCalled atomic.Int32

	// Configurable Sync
	syncBlockCh chan struct{}
	syncItems   []vault.Item
	syncFolders []vault.Folder
	syncRev     string
	syncErr     error

	// Configurable Create
	createErr  error
	createItem vault.Item

	// Configurable Update
	updateErr  error
	updateItem vault.Item

	// Configurable Trash
	trashErr error

	// Configurable Restore
	restoreErr  error
	restoreItem vault.Item

	// Configurable Delete
	deleteErr error

	// Configurable two-factor login
	beginChallenge   *auth.TwoFactorChallenge
	beginCalled      bool
	completeProvider auth.TwoFactorProvider
	completeCode     string

	// Override hooks (for testing lifecycle)
	onLogin      func(ctx context.Context, email, password string) error
	loginEnterCh chan struct{} // signaled when Login is entered (before hook)
	onCreate     func(ctx context.Context, item vault.Item) (vault.Item, error)
	onSync       func(ctx context.Context) ([]vault.Item, []vault.Folder, string, error)
	syncEnterCh  chan struct{} // signaled when Sync enters (before block)

	// RefreshTokenBundle configurable
	refreshTokenBundleFunc    func(ctx context.Context, bundle session.TokenBundle) (session.TokenBundle, error)
	refreshTokenBundleResult  session.TokenBundle
	refreshTokenBundleErr     error
	refreshTokenBundleCallCnt atomic.Int32

	// ExportSession configurable
	exportMaterial   session.UnlockMaterial
	exportTokens     session.TokenBundle
	exportSessionErr error
	exportCallCnt    atomic.Int32

	// RestoreSession configurable
	restoreCallCnt    int
	restoreMaterial   session.UnlockMaterial
	restoreTokens     session.TokenBundle
	restoreSessionErr error
}

func (r *fakeRemote) Login(ctx context.Context, email, password string) error {
	r.mu.Lock()
	onLogin := r.onLogin
	enterCh := r.loginEnterCh
	r.mu.Unlock()

	// Signal that Login has been entered (non-blocking).
	if enterCh != nil {
		select {
		case enterCh <- struct{}{}:
		default:
		}
	}

	if onLogin != nil {
		return onLogin(ctx, email, password)
	}

	r.mu.Lock()
	r.loginCalled = true
	r.mu.Unlock()
	return nil
}

func (r *fakeRemote) BeginLogin(ctx context.Context, email, password string) (*auth.TwoFactorChallenge, error) {
	if err := r.Login(ctx, email, password); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.beginCalled = true
	return r.beginChallenge, nil
}

func (r *fakeRemote) CompleteTwoFactorLogin(_ context.Context, _ *auth.TwoFactorChallenge, provider auth.TwoFactorProvider, code string, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completeProvider = provider
	r.completeCode = code
	return nil
}

func (r *fakeRemote) CompleteTwoFactor(_ context.Context, _, _ string, _ bool) error {
	return nil
}

func (r *fakeRemote) Lock(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lockCalled = true
	return nil
}

func (r *fakeRemote) Revision(_ context.Context) (string, error) {
	r.syncStarted.Store(true)
	return r.revisionRev, r.revisionErr
}

func (r *fakeRemote) Sync(ctx context.Context) ([]vault.Item, []vault.Folder, string, error) {
	r.syncCalled.Add(1)

	r.mu.Lock()
	onSync := r.onSync
	blockCh := r.syncBlockCh
	enterCh := r.syncEnterCh
	items := r.syncItems
	folders := r.syncFolders
	rev := r.syncRev
	err := r.syncErr
	r.mu.Unlock()

	// Signal that Sync has been entered (non-blocking).
	if enterCh != nil {
		select {
		case enterCh <- struct{}{}:
		default:
		}
	}

	if onSync != nil {
		return onSync(ctx)
	}

	if blockCh != nil {
		select {
		case <-ctx.Done():
			return nil, nil, "", ctx.Err()
		case <-blockCh:
		}
	}

	return items, folders, rev, err
}

func (r *fakeRemote) Create(ctx context.Context, item vault.Item) (vault.Item, error) {
	r.mu.Lock()
	onCreate := r.onCreate
	err := r.createErr
	result := r.createItem
	r.mu.Unlock()

	if onCreate != nil {
		return onCreate(ctx, item)
	}

	if err != nil {
		return vault.Item{}, err
	}
	if result.ID == "" {
		result = item
	}
	return result, nil
}

func (r *fakeRemote) Update(_ context.Context, id string, item vault.Item) (vault.Item, error) {
	r.mu.Lock()
	err := r.updateErr
	result := r.updateItem
	r.mu.Unlock()
	if err != nil {
		return vault.Item{}, err
	}
	if result.ID == "" {
		result = item
		result.ID = id
	}
	return result, nil
}

func (r *fakeRemote) Trash(_ context.Context, _ string) error {
	r.mu.Lock()
	err := r.trashErr
	r.mu.Unlock()
	return err
}

func (r *fakeRemote) Restore(_ context.Context, id string) (vault.Item, error) {
	r.mu.Lock()
	err := r.restoreErr
	result := r.restoreItem
	r.mu.Unlock()
	if err != nil {
		return vault.Item{}, err
	}
	return result, nil
}

func (r *fakeRemote) Delete(_ context.Context, _ string) error {
	r.mu.Lock()
	err := r.deleteErr
	r.mu.Unlock()
	return err
}

func (r *fakeRemote) ListAttachments(_ context.Context, _ string) ([]vault.Attachment, error) {
	return nil, nil
}

func (r *fakeRemote) DownloadAttachment(_ context.Context, _, _ string, _ io.Writer) error {
	return nil
}

func (r *fakeRemote) UploadAttachment(_ context.Context, _ string, _ string, _ int64, _ io.Reader) (vault.Attachment, error) {
	return vault.Attachment{}, nil
}

func (r *fakeRemote) DeleteAttachment(_ context.Context, _, _ string) error {
	return nil
}

func (r *fakeRemote) ExportSession(_ context.Context) (session.UnlockMaterial, session.TokenBundle, error) {
	r.exportCallCnt.Add(1)
	return r.exportMaterial, r.exportTokens, r.exportSessionErr
}

func (r *fakeRemote) RestoreSession(_ context.Context, material session.UnlockMaterial, tokens session.TokenBundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.restoreCallCnt++
	r.restoreMaterial = material.Clone()
	r.restoreTokens = tokens.Clone()
	if r.restoreSessionErr != nil {
		return r.restoreSessionErr
	}
	return nil
}

func (r *fakeRemote) RefreshTokenBundle(ctx context.Context, bundle session.TokenBundle) (session.TokenBundle, error) {
	r.refreshTokenBundleCallCnt.Add(1)
	r.mu.Lock()
	fn := r.refreshTokenBundleFunc
	res := r.refreshTokenBundleResult
	err := r.refreshTokenBundleErr
	r.mu.Unlock()

	if fn != nil {
		return fn(ctx, bundle)
	}
	return res, err
}

type fakeCache struct {
	mu          sync.Mutex
	data        *cache.Snapshot
	loadErr     error
	loadCall    int
	saveStarted chan struct{}
	saveBlock   chan struct{}
	saveCalled  int
}

func (c *fakeCache) Load(_ context.Context) (cache.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadCall++
	if c.loadErr != nil {
		return cache.Snapshot{}, c.loadErr
	}
	if c.data != nil {
		return *c.data, nil
	}
	return cache.Snapshot{}, nil
}

func (c *fakeCache) Save(ctx context.Context, _ cache.Snapshot) error {
	c.mu.Lock()
	c.saveCalled++
	started := c.saveStarted
	block := c.saveBlock
	c.mu.Unlock()

	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (c *fakeCache) Clear(_ context.Context) error {
	return nil
}

func (c *fakeCache) Path() string {
	return "/fake/path"
}

type fakeSecretBox struct{}

func (f *fakeSecretBox) Seal(plaintext, key []byte) ([]byte, error) {
	return plaintext, nil
}

func (f *fakeSecretBox) Open(ciphertext, key []byte) ([]byte, error) {
	return ciphertext, nil
}

// ---------------------------------------------------------------------------
// Fake credential store
// ---------------------------------------------------------------------------

type fakeCredentialStore struct {
	mu sync.Mutex

	checkAvailableErr   error
	checkAvailableCalls int

	tokenBundle      session.TokenBundle
	savedTokenBundle session.TokenBundle
	loadTokenErr     error
	loadTokenCalls   int
	saveTokenCalled  int
	delTokenCalls    int

	envelope            session.UnlockEnvelope
	savedUnlockEnvelope session.UnlockEnvelope
	loadEnvelopeErr     error
	loadEnvCalls        int
	saveEnvCalled       int
	delEnvCalls         int
}

func (cs *fakeCredentialStore) CheckAvailable(_ context.Context) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.checkAvailableCalls++
	return cs.checkAvailableErr
}

func (cs *fakeCredentialStore) SaveTokenBundle(_ context.Context, _ session.AccountRef, bundle session.TokenBundle) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.saveTokenCalled++
	cs.savedTokenBundle = bundle
	return nil
}

func (cs *fakeCredentialStore) LoadTokenBundle(_ context.Context, _ session.AccountRef) (session.TokenBundle, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadTokenCalls++
	return cs.tokenBundle, cs.loadTokenErr
}

func (cs *fakeCredentialStore) DeleteTokenBundle(_ context.Context, _ session.AccountRef) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.delTokenCalls++
	return nil
}

func (cs *fakeCredentialStore) SaveUnlockEnvelope(_ context.Context, _ session.AccountRef, env session.UnlockEnvelope) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.saveEnvCalled++
	cs.savedUnlockEnvelope = env
	return nil
}

func (cs *fakeCredentialStore) LoadUnlockEnvelope(_ context.Context, _ session.AccountRef) (session.UnlockEnvelope, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadEnvCalls++
	return cs.envelope, cs.loadEnvelopeErr
}

func (cs *fakeCredentialStore) DeleteUnlockEnvelope(_ context.Context, _ session.AccountRef) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.delEnvCalls++
	return nil
}

// ---------------------------------------------------------------------------
// Fake boot ID provider
// ---------------------------------------------------------------------------

type fakeBootID struct {
	mu  sync.Mutex
	id  string
	err error
}

func (b *fakeBootID) BootID(_ context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.id, b.err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildValidSnapshot creates a cache.Snapshot containing items as a PlainSnapshot,
// encrypted (via secretbox) with an Argon2id-derived key from the given password.
func buildValidSnapshot(t *testing.T, password string, items []vault.Item, folders []vault.Folder) cache.Snapshot {
	t.Helper()

	itemsJSON, err := json.Marshal(items)
	require.NoError(t, err)

	foldersJSON, err := json.Marshal(folders)
	require.NoError(t, err)

	plain := cache.PlainSnapshot{
		AccountHash:  "test-account-hash",
		LastRevision: "rev-1",
		SavedAt:      time.Now(),
		ItemsJSON:    itemsJSON,
		FoldersJSON:  foldersJSON,
	}

	plainJSON, err := json.Marshal(plain)
	require.NoError(t, err)

	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	box := &fakeSecretBox{}
	ciphertext, err := box.Seal(plainJSON, key)
	require.NoError(t, err)

	return cache.Snapshot{
		Version:         cache.Version,
		AccountHash:     "test-account-hash",
		LastRevision:    "rev-1",
		SavedAt:         time.Now(),
		CacheKeySalt:    salt,
		VaultCiphertext: ciphertext,
	}
}

// consumeEvents reads all events from a channel until no more arrive within
// a short timeout, returning them in order.
func consumeEvents(t *testing.T, ch <-chan Event, timeout time.Duration) []Event {
	t.Helper()
	var result []Event
	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				return result
			}
			result = append(result, evt)
		case <-time.After(timeout):
			return result
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSearchLockedReturnsError(t *testing.T) {
	svc := NewService(Deps{})
	_, err := svc.Search(context.Background(), "git", 10)
	require.ErrorIs(t, err, coreerrors.ErrLocked)
}

func TestUnlockInstallsCacheIndexBeforeSync(t *testing.T) {
	gitItem := vault.Item{
		ID:   "item-1",
		Name: "GitHub",
		Type: vault.ItemTypeLogin,
		Login: &vault.Login{
			Username: "user@github.com",
		},
	}

	snap := buildValidSnapshot(t, "mypassword", []vault.Item{gitItem}, nil)

	fakeR := &fakeRemote{}
	fakeR.revisionRev = "rev-2"

	svc := NewService(Deps{
		Remote:    fakeR,
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	err := svc.Unlock(context.Background(), "user@test.com", "mypassword")
	require.NoError(t, err)

	// Search should immediately return the cached GitHub item.
	results, err := svc.Search(context.Background(), "git", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "GitHub", results[0].Item.Name)

	// Eventually the sync worker should have checked revision.
	require.Eventually(t, func() bool {
		return fakeR.syncStarted.Load()
	}, 1*time.Second, 10*time.Millisecond, "sync worker should have started")
}

func TestLockClearsState(t *testing.T) {
	gitItem := vault.Item{
		ID:   "item-1",
		Name: "GitHub",
		Type: vault.ItemTypeLogin,
	}
	snap := buildValidSnapshot(t, "pw", []vault.Item{gitItem}, nil)

	svc := NewService(Deps{
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	// Unlock
	err := svc.Unlock(context.Background(), "user@test.com", "pw")
	require.NoError(t, err)

	// Verify unlocked state
	_, err = svc.Search(context.Background(), "git", 10)
	require.NoError(t, err)

	// Lock
	err = svc.Lock(context.Background())
	require.NoError(t, err)

	// Search after lock returns error
	_, err = svc.Search(context.Background(), "git", 10)
	require.ErrorIs(t, err, coreerrors.ErrLocked)

	// Items after lock returns error
	_, err = svc.Items(context.Background())
	require.ErrorIs(t, err, coreerrors.ErrLocked)

	// Verify state is locked
	svc.mu.Lock()
	require.Equal(t, auth.LockStateLocked, svc.state)
	require.Nil(t, svc.items)
	require.Nil(t, svc.index)
	svc.mu.Unlock()
}

func TestEventsEmittedForUnlock(t *testing.T) {
	gitItem := vault.Item{
		ID:   "item-1",
		Name: "GitHub",
		Type: vault.ItemTypeLogin,
	}
	snap := buildValidSnapshot(t, "pw", []vault.Item{gitItem}, nil)

	fakeR := &fakeRemote{}
	fakeR.revisionRev = "rev-2"

	svc := NewService(Deps{
		Remote:    fakeR,
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	err := svc.Unlock(context.Background(), "user@test.com", "pw")
	require.NoError(t, err)

	// Collect events with a generous timeout.
	events := consumeEvents(t, svc.events, 200*time.Millisecond)

	// Build a set of observed kinds.
	seen := make(map[EventKind]bool)
	for _, e := range events {
		seen[e.Kind] = true
	}

	require.True(t, seen[Unlocking], "expected Unlocking event")
	require.True(t, seen[CacheLoaded], "expected CacheLoaded event")
	require.True(t, seen[IndexReady], "expected IndexReady event")
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

func (s *Service) pendingMutationsForTest() []coresync.OutboxMutation {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]coresync.OutboxMutation, len(s.outbox))
	copy(result, s.outbox)
	return result
}

func (s *Service) conflictsForTest() []coresync.Conflict {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]coresync.Conflict, len(s.conflicts))
	copy(result, s.conflicts)
	return result
}

func (s *Service) installUnlockedStateForTest(key []byte, items []vault.Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = auth.LockStateUnlocked
	s.cacheKey = append(s.cacheKey[:0], key...)
	s.items = append(s.items[:0], items...)
	s.rebuildIndexLocked()
}

// ---------------------------------------------------------------------------
// Offline mutation tests
// ---------------------------------------------------------------------------

func TestCreateQueuesPendingWhenRemoteFails(t *testing.T) {
	fr := &fakeRemote{
		createErr: context.DeadlineExceeded,
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.mu.Unlock()

	item, err := svc.Create(context.Background(), vault.Item{Name: "Offline"})
	require.NoError(t, err)
	require.Equal(t, vault.SyncStatusPending, item.SyncStatus)
	require.Contains(t, item.ID, "local-")

	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 1)
	require.Equal(t, coresync.MutationCreate, pending[0].Kind)
	require.Equal(t, item.ID, pending[0].ItemID)

	// Verify item exists in local list.
	items, err := svc.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "Offline", items[0].Name)
}

func TestCreateOnlineUpdatesLocalSynced(t *testing.T) {
	fr := &fakeRemote{
		createItem: vault.Item{ID: "remote-1", Name: "SyncedItem", RevisionDate: time.Now()},
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.mu.Unlock()

	item, err := svc.Create(context.Background(), vault.Item{Name: "NewItem"})
	require.NoError(t, err)
	require.Equal(t, "remote-1", item.ID)
	require.Equal(t, vault.SyncStatusSynced, item.SyncStatus)

	// No pending mutations.
	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 0)

	// Search should find the item.
	results, err := svc.Search(context.Background(), "SyncedItem", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "remote-1", results[0].Item.ID)
}

func TestSyncConflictMarksItem(t *testing.T) {
	localItem := vault.Item{
		ID:   "item-1",
		Name: "LocalItem",
		Type: vault.ItemTypeLogin,
	}

	fr := &fakeRemote{
		revisionRev: "new-rev",
		syncItems: []vault.Item{
			{ID: "item-1", Name: "RemoteItem", RevisionDate: time.Now(), Type: vault.ItemTypeLogin},
		},
		syncFolders: nil,
		syncRev:     "new-rev",
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.items = []vault.Item{localItem}
	svc.outbox = []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationUpdate, ItemID: "item-1"},
	}
	svc.rebuildIndexLocked()
	svc.mu.Unlock()

	// Run sync.
	svc.syncOnce(context.Background())

	// Check item is marked as conflict.
	svc.mu.Lock()
	require.Len(t, svc.items, 1)
	require.Equal(t, vault.SyncStatusConflict, svc.items[0].SyncStatus)
	require.NotEmpty(t, svc.items[0].ConflictID)
	conflictCount := len(svc.conflicts)
	svc.mu.Unlock()

	require.Equal(t, 1, conflictCount)
}

// ---------------------------------------------------------------------------
// Config copy / UpdateConfig tests
// ---------------------------------------------------------------------------

func TestConfigReturnsCopy(t *testing.T) {
	svc := NewService(Deps{
		Config: &coreconfig.Config{
			Bitwarden: coreconfig.Bitwarden{Email: "test@example.com"},
		},
	})

	c1 := svc.Config()
	c2 := svc.Config()

	// Both should be non-nil and equal.
	require.NotNil(t, c1)
	require.NotNil(t, c2)
	require.Equal(t, "test@example.com", c1.Bitwarden.Email)

	// Mutating c1 must NOT affect c2 or the service.
	c1.Bitwarden.Email = "mutated@example.com"
	require.Equal(t, "test@example.com", c2.Bitwarden.Email)

	// Re-fetching returns the original (unmutated) value.
	c3 := svc.Config()
	require.Equal(t, "test@example.com", c3.Bitwarden.Email)

	// c1 and c2 must point to different allocations.
	require.NotSame(t, c1, c2)
}

func TestConfigReturnsDefaultWhenNil(t *testing.T) {
	svc := NewService(Deps{})
	c := svc.Config()
	require.NotNil(t, c)
	// Should have default values.
	require.Equal(t, coreconfig.RegionUS, c.Bitwarden.Region)
}

func TestUpdateConfigReplacesConfig(t *testing.T) {
	svc := NewService(Deps{})

	newCfg := coreconfig.Default()
	newCfg.Bitwarden.Email = "updated@example.com"
	newCfg.Bitwarden.Region = coreconfig.RegionEU
	err := svc.UpdateConfig(context.Background(), newCfg)
	require.NoError(t, err)

	c := svc.Config()
	require.Equal(t, "updated@example.com", c.Bitwarden.Email)
	require.Equal(t, coreconfig.RegionEU, c.Bitwarden.Region)
}

func TestUpdateConfigImmutability(t *testing.T) {
	svc := NewService(Deps{})

	original := coreconfig.Default()
	original.Bitwarden.Email = "original@example.com"
	err := svc.UpdateConfig(context.Background(), original)
	require.NoError(t, err)

	// Mutate the original reference after update.
	original.Bitwarden.Email = "mutated@example.com"

	// The service should still have the original value.
	c := svc.Config()
	require.Equal(t, "original@example.com", c.Bitwarden.Email)
}

func TestUpdateConfigRespectsContextCancel(t *testing.T) {
	svc := NewService(Deps{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Already cancelled.

	newCfg := coreconfig.Default()
	err := svc.UpdateConfig(ctx, newCfg)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestUpdateConfigRejectsInvalidConfig(t *testing.T) {
	svc := NewService(Deps{})

	// Invalid ui_scale (5.0 is out of range) should be rejected.
	badCfg := coreconfig.Default()
	badCfg.Appearance.UIScale = 5.0
	err := svc.UpdateConfig(context.Background(), badCfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "config update")
}

func TestUpdateConfigToleratesOnlyMissingEmail(t *testing.T) {
	svc := NewService(Deps{})

	// Only missing email, everything else valid defaults.
	nullCfg := coreconfig.Default()
	nullCfg.Bitwarden.Email = ""
	err := svc.UpdateConfig(context.Background(), nullCfg)
	require.NoError(t, err, "missing email alone should be tolerated")

	// Missing email AND invalid UIScale should be rejected.
	badCfg := coreconfig.Default()
	badCfg.Bitwarden.Email = ""
	badCfg.Appearance.UIScale = 5.0
	err = svc.UpdateConfig(context.Background(), badCfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "config update")
}

func TestUpdateConfigEmitsEvent(t *testing.T) {
	svc := NewService(Deps{})

	err := svc.UpdateConfig(context.Background(), coreconfig.Default())
	require.NoError(t, err)

	events := consumeEvents(t, svc.events, 100*time.Millisecond)
	found := false
	for _, e := range events {
		if e.Kind == SyncUpdated && e.Message == "config updated" {
			found = true
			break
		}
	}
	require.True(t, found, "expected SyncUpdated event with 'config updated' message")
}

func TestLockCancelsSyncInstall(t *testing.T) {
	fr := &fakeRemote{
		revisionRev: "rev2",
		syncBlockCh: make(chan struct{}),
		syncEnterCh: make(chan struct{}, 1),
		syncItems:   []vault.Item{{ID: "remote-1", Name: "ShouldNotAppear"}},
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.items = []vault.Item{{ID: "local-1", Name: "Original"}}
	svc.rebuildIndexLocked()
	svc.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.syncOnce(ctx)
	}()

	// Wait for syncOnce to reach Remote.Sync (which blocks on syncBlockCh).
	<-fr.syncEnterCh

	// Cancel context — simulates Lock cancelling workers.
	cancel()

	// Unblock Sync after cancel has taken effect.
	close(fr.syncBlockCh)

	wg.Wait()

	// Verify original items remain (remote items were never installed).
	svc.mu.Lock()
	require.Len(t, svc.items, 1)
	require.Equal(t, "local-1", svc.items[0].ID)
	require.Equal(t, "Original", svc.items[0].Name)
	svc.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Outbox-from-cache tests
// ---------------------------------------------------------------------------

func TestUnlockLoadsOutboxFromCacheAndOutboxStore(t *testing.T) {
	item := vault.Item{ID: "item-1", Name: "Test", Type: vault.ItemTypeLogin}
	itemsJSON, _ := json.Marshal([]vault.Item{item})
	foldersJSON, _ := json.Marshal([]vault.Folder{})

	// Outbox mutation stored in PlainSnapshot.OutboxJSON
	cachedMutations := []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "item-cached", Payload: []byte(`{"id":"item-cached"}`)},
	}
	outboxJSON, _ := json.Marshal(cachedMutations)

	plain := cache.PlainSnapshot{
		AccountHash:  "test-account-hash",
		LastRevision: "rev-1",
		SavedAt:      time.Now(),
		ItemsJSON:    itemsJSON,
		FoldersJSON:  foldersJSON,
		OutboxJSON:   outboxJSON,
	}
	plainJSON, _ := json.Marshal(plain)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte("mypassword"), salt, 3, 64*1024, 4, 32)
	box := &fakeSecretBox{}
	ciphertext, _ := box.Seal(plainJSON, key)

	snap := cache.Snapshot{
		Version:         cache.Version,
		AccountHash:     "test-account-hash",
		LastRevision:    "rev-1",
		SavedAt:         time.Now(),
		CacheKeySalt:    salt,
		VaultCiphertext: ciphertext,
	}

	// Outbox store has additional mutations.
	fo := &fakeOutbox{
		loadData: []coresync.OutboxMutation{
			{ID: "m2", Kind: coresync.MutationUpdate, ItemID: "item-store", Payload: []byte(`{"id":"item-store"}`)},
		},
	}

	svc := NewService(Deps{
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
		Outbox:    fo,
	})

	err := svc.Unlock(context.Background(), "user@test.com", "mypassword")
	require.NoError(t, err)

	// Verify both outbox sources are loaded.
	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 2)

	// Collect IDs.
	ids := make(map[string]bool)
	for _, m := range pending {
		ids[m.ID] = true
	}
	require.True(t, ids["m1"], "expected cached outbox mutation m1")
	require.True(t, ids["m2"], "expected outbox store mutation m2")
}

func TestUnlockDeduplicatesOutboxMutations(t *testing.T) {
	item := vault.Item{ID: "item-1", Name: "Test", Type: vault.ItemTypeLogin}
	itemsJSON, _ := json.Marshal([]vault.Item{item})
	foldersJSON, _ := json.Marshal([]vault.Folder{})

	// Both cache and OutboxStore provide mutation ID m1.
	cachedMutations := []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "item-cached", Payload: []byte(`{"id":"item-cached"}`)},
	}
	outboxJSON, _ := json.Marshal(cachedMutations)

	plain := cache.PlainSnapshot{
		AccountHash:  "test-account-hash",
		LastRevision: "rev-1",
		SavedAt:      time.Now(),
		ItemsJSON:    itemsJSON,
		FoldersJSON:  foldersJSON,
		OutboxJSON:   outboxJSON,
	}
	plainJSON, _ := json.Marshal(plain)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte("mypassword"), salt, 3, 64*1024, 4, 32)
	box := &fakeSecretBox{}
	ciphertext, _ := box.Seal(plainJSON, key)

	snap := cache.Snapshot{
		Version:         cache.Version,
		AccountHash:     "test-account-hash",
		LastRevision:    "rev-1",
		SavedAt:         time.Now(),
		CacheKeySalt:    salt,
		VaultCiphertext: ciphertext,
	}

	// Outbox store also has m1 (duplicate) plus a unique m3.
	fo := &fakeOutbox{
		loadData: []coresync.OutboxMutation{
			{ID: "m1", Kind: coresync.MutationUpdate, ItemID: "item-store", Payload: []byte(`{"id":"item-store"}`)},
			{ID: "m3", Kind: coresync.MutationDelete, ItemID: "item-store", Payload: []byte(`{"id":"item-store"}`)},
		},
	}

	svc := NewService(Deps{
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
		Outbox:    fo,
	})

	err := svc.Unlock(context.Background(), "user@test.com", "mypassword")
	require.NoError(t, err)

	// Only one m1 and one m3 should be present (deduplicated).
	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 2, "expected 2 unique mutations after dedup")

	m1Count := 0
	m3Count := 0
	for _, m := range pending {
		switch m.ID {
		case "m1":
			m1Count++
		case "m3":
			m3Count++
		}
	}
	require.Equal(t, 1, m1Count, "m1 should appear exactly once")
	require.Equal(t, 1, m3Count, "m3 should appear exactly once")
}

func TestLockZeroesCacheKey(t *testing.T) {
	item := vault.Item{ID: "item-1", Name: "Test", Type: vault.ItemTypeLogin}
	snap := buildValidSnapshot(t, "mypassword", []vault.Item{item}, nil)

	svc := NewService(Deps{
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	err := svc.Unlock(context.Background(), "user@test.com", "mypassword")
	require.NoError(t, err)

	// Capture the cacheKey slice reference and copy its contents before Lock.
	svc.mu.Lock()
	preKey := svc.cacheKey
	preCopy := make([]byte, len(preKey))
	copy(preCopy, preKey)
	svc.mu.Unlock()

	require.NotNil(t, preKey, "cacheKey should be set after unlock")
	require.NotEmpty(t, preCopy, "cacheKey copy should be non-empty")

	err = svc.Lock(context.Background())
	require.NoError(t, err)

	// After Lock, the original backing array must be zeroed.
	for i := range preCopy {
		if preKey[i] != 0 {
			t.Fatalf("cacheKey byte %d not zeroed: got %d", i, preKey[i])
		}
	}

	// The copy we made before Lock should differ from the zeroed array
	// (unless the original was already all zeros, which shouldn't happen).
	allZero := true
	for _, b := range preCopy {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero, "pre-lock cacheKey should not be all zeros")

	svc.mu.Lock()
	require.Nil(t, svc.cacheKey, "cacheKey should be nil after Lock")
	svc.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Outbox replay tests
// ---------------------------------------------------------------------------

func TestSyncReplaysOutboxBeforeClearing(t *testing.T) {
	// Create an item that the outbox will try to create remotely.
	pendingItem := vault.Item{
		ID:   "pending-1",
		Name: "PendingCreate",
		Type: vault.ItemTypeLogin,
	}
	payload, _ := json.Marshal(pendingItem)

	// Initial items in local state (will be replaced by remote sync after replay).
	localItem := vault.Item{
		ID:   "existing-1",
		Name: "LocalPreSync",
		Type: vault.ItemTypeLogin,
	}

	createCalled := make(chan struct{}, 1)

	// First Sync call returns the initial remote state (no conflict with pending create).
	// After replay, second Sync call returns the final state including replayed create.
	syncCallCount := 0
	fr := &fakeRemote{
		revisionRev: "rev2",
		syncItems:   []vault.Item{{ID: "existing-1", Name: "RemoteVersion", RevisionDate: time.Now(), Type: vault.ItemTypeLogin}},
		syncFolders: nil,
		syncRev:     "rev3",
		onCreate: func(ctx context.Context, item vault.Item) (vault.Item, error) {
			createCalled <- struct{}{}
			// Return a valid item to simulate successful create.
			return vault.Item{ID: "remote-pending-1", Name: "CreatedRemotely", RevisionDate: time.Now()}, nil
		},
	}
	fr.onSync = func(ctx context.Context) ([]vault.Item, []vault.Folder, string, error) {
		syncCallCount++
		if syncCallCount == 1 {
			return []vault.Item{{ID: "existing-1", Name: "RemoteVersion", RevisionDate: time.Now(), Type: vault.ItemTypeLogin}},
				nil, "rev3", nil
		}
		// Second call includes the newly created item.
		return []vault.Item{
			{ID: "existing-1", Name: "RemoteVersion", RevisionDate: time.Now(), Type: vault.ItemTypeLogin},
			{ID: "remote-pending-1", Name: "CreatedRemotely", RevisionDate: time.Now(), Type: vault.ItemTypeLogin},
		}, nil, "rev4", nil
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.items = []vault.Item{localItem}
	svc.outbox = []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "pending-1", Payload: payload},
	}
	svc.rebuildIndexLocked()
	svc.mu.Unlock()

	svc.syncOnce(context.Background())

	// Verify Create was called on remote.
	select {
	case <-createCalled:
		// Success
	case <-time.After(time.Second):
		t.Fatal("remote.Create was not called during sync")
	}

	// Verify outbox is cleared after successful sync.
	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 0, "outbox should be cleared after successful replay and sync")

	// Verify remote state is installed (should have 2 items from second Sync call).
	items, err := svc.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 2, "expected 2 items after replay")
	require.Equal(t, "RemoteVersion", items[0].Name)
	require.Equal(t, "CreatedRemotely", items[1].Name)
}

func TestSyncPreservesConcurrentOutboxMutations(t *testing.T) {
	pendingItem := vault.Item{ID: "pending-1", Name: "PendingCreate", Type: vault.ItemTypeLogin}
	payload, _ := json.Marshal(pendingItem)
	concurrentItem := vault.Item{ID: "concurrent-1", Name: "Concurrent", Type: vault.ItemTypeLogin}
	concurrentPayload, _ := json.Marshal(concurrentItem)

	syncCallCount := 0
	fr := &fakeRemote{revisionRev: "rev2"}
	var svc *Service
	fr.onCreate = func(ctx context.Context, item vault.Item) (vault.Item, error) {
		// Simulate a user queuing another mutation while the sync worker is
		// replaying its original outbox snapshot. That new mutation must not be
		// cleared with the replayed snapshot.
		svc.mu.Lock()
		svc.outbox = append(svc.outbox, coresync.OutboxMutation{ID: "m2", Kind: coresync.MutationCreate, ItemID: "concurrent-1", Payload: concurrentPayload})
		svc.mu.Unlock()
		return vault.Item{ID: "remote-pending-1", Name: item.Name, RevisionDate: time.Now(), Type: item.Type}, nil
	}
	fr.onSync = func(ctx context.Context) ([]vault.Item, []vault.Folder, string, error) {
		syncCallCount++
		if syncCallCount == 1 {
			return []vault.Item{{ID: "remote-1", Name: "Remote", RevisionDate: time.Now(), Type: vault.ItemTypeLogin}}, nil, "rev3", nil
		}
		return []vault.Item{{ID: "remote-1", Name: "Remote", RevisionDate: time.Now(), Type: vault.ItemTypeLogin}, {ID: "remote-pending-1", Name: "PendingCreate", RevisionDate: time.Now(), Type: vault.ItemTypeLogin}}, nil, "rev4", nil
	}

	svc = NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.outbox = []coresync.OutboxMutation{{ID: "m1", Kind: coresync.MutationCreate, ItemID: "pending-1", Payload: payload}}
	svc.rebuildIndexLocked()
	svc.mu.Unlock()

	svc.syncOnce(context.Background())

	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 1, "concurrent mutation should be preserved")
	require.Equal(t, "m2", pending[0].ID)
}

func TestSyncKeepsOutboxWhenReplayFails(t *testing.T) {
	localItem := vault.Item{
		ID:   "item-1",
		Name: "LocalItem",
		Type: vault.ItemTypeLogin,
	}
	payload, _ := json.Marshal(localItem)

	fr := &fakeRemote{
		revisionRev: "rev2",
		createErr:   fmt.Errorf("network error"),
		syncItems:   []vault.Item{{ID: "remote-1", Name: "RemoteShouldNotInstall", RevisionDate: time.Now(), Type: vault.ItemTypeLogin}},
		syncFolders: nil,
		syncRev:     "rev3",
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.items = []vault.Item{localItem}
	svc.outbox = []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationCreate, ItemID: "item-1", Payload: payload},
	}
	svc.rebuildIndexLocked()
	svc.mu.Unlock()

	svc.syncOnce(context.Background())

	// Verify outbox is still intact after replay failure.
	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 1, "outbox should remain after replay failure")
	require.Equal(t, "m1", pending[0].ID)

	// Verify remote state was NOT installed.
	items, err := svc.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "LocalItem", items[0].Name)
}

// ---------------------------------------------------------------------------
// Conflict resolution tests
// ---------------------------------------------------------------------------

func TestResolveConflictDuplicateLocalQueuesCreate(t *testing.T) {
	localItem := vault.Item{
		ID:   "item-1",
		Name: "ConflictedItem",
		Type: vault.ItemTypeLogin,
	}

	fr := &fakeRemote{
		revisionRev: "rev2",
		syncItems: []vault.Item{
			{ID: "item-1", Name: "RemoteVersion", RevisionDate: time.Now(), Type: vault.ItemTypeLogin},
		},
		syncFolders: nil,
		syncRev:     "rev3",
	}

	svc := NewService(Deps{Remote: fr})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.items = []vault.Item{localItem}
	svc.outbox = []coresync.OutboxMutation{
		{ID: "m1", Kind: coresync.MutationUpdate, ItemID: "item-1", Payload: []byte(`{"name":"UpdatedLocally"}`)},
	}
	svc.rebuildIndexLocked()
	svc.mu.Unlock()

	// Run sync to trigger conflict detection.
	svc.syncOnce(context.Background())

	// Verify conflict was detected.
	conflicts := svc.conflictsForTest()
	require.Len(t, conflicts, 1, "expected 1 conflict")
	require.Equal(t, "item-1", conflicts[0].ItemID)

	// Verify pending remote items are stored.
	svc.mu.Lock()
	require.Len(t, svc.pendingRemoteItems, 1)
	require.Equal(t, "RemoteVersion", svc.pendingRemoteItems[0].Name)
	svc.mu.Unlock()

	// Resolve by duplicating local.
	err := svc.ResolveConflict(context.Background(), conflicts[0].ID, coresync.ResolutionDuplicateLocal)
	require.NoError(t, err)

	// Verify a new item with local-* ID was added.
	items, err := svc.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 2, "expected original + duplicate")

	var original, duplicate vault.Item
	for _, it := range items {
		if it.ID == "item-1" {
			original = it
		} else {
			duplicate = it
		}
	}

	require.Equal(t, "item-1", original.ID)
	require.Empty(t, original.ConflictID, "original should have conflict cleared")
	require.Equal(t, vault.SyncStatusSynced, original.SyncStatus, "original should no longer be marked conflicted")
	require.Equal(t, "RemoteVersion", original.Name, "original should resolve to remote version")
	require.Contains(t, duplicate.ID, "local-", "duplicate should have local ID")
	require.Equal(t, vault.SyncStatusPending, duplicate.SyncStatus, "duplicate should be pending")

	// Verify a create mutation was queued for the duplicate, and the original
	// conflicting update was removed so it cannot replay/re-conflict.
	pending := svc.pendingMutationsForTest()
	require.Len(t, pending, 1)
	require.Equal(t, coresync.MutationCreate, pending[0].Kind)
	require.Equal(t, duplicate.ID, pending[0].ItemID)

	// Verify no conflicts remain.
	require.Len(t, svc.conflictsForTest(), 0)
}

// ---------------------------------------------------------------------------
// Event safety tests
// ---------------------------------------------------------------------------

func TestShutdownWaitsForAsyncCacheSave(t *testing.T) {
	cacheStore := &fakeCache{saveStarted: make(chan struct{}, 1), saveBlock: make(chan struct{})}
	remote := &fakeRemote{
		revisionRev: "rev-1",
		syncRev:     "rev-1",
		syncItems: []vault.Item{{
			ID:           "item-1",
			Name:         "Example",
			Type:         vault.ItemTypeLogin,
			RevisionDate: time.Now(),
		}},
	}
	svc := NewService(Deps{Remote: remote, Cache: cacheStore, SecretBox: &fakeSecretBox{}, Config: coreconfig.Default()})

	require.NoError(t, svc.Unlock(context.Background(), "me@example.com", "password"))
	require.Eventually(t, func() bool {
		select {
		case <-cacheStore.saveStarted:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- svc.Shutdown(context.Background()) }()

	require.Never(t, func() bool {
		select {
		case <-shutdownDone:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, 5*time.Millisecond, "shutdown should wait for in-flight cache save")

	close(cacheStore.saveBlock)
	require.NoError(t, <-shutdownDone)
}

func TestEmitAfterShutdownDoesNotPanic(t *testing.T) {
	svc := NewService(Deps{})

	// Shutdown.
	err := svc.Shutdown(context.Background())
	require.NoError(t, err)

	// emit must not panic.
	require.NotPanics(t, func() {
		svc.emit(SyncUpdated, "after shutdown")
		svc.emit(SyncFailed, "another after shutdown")
	})

	// The channel should be closed.
	_, ok := <-svc.Events()
	require.False(t, ok, "events channel should be closed")
}

// ---------------------------------------------------------------------------
// Lock/Unlock interleaving tests
// ---------------------------------------------------------------------------

func TestLockDuringUnlockPreventsInstall(t *testing.T) {
	loginBlockCh := make(chan struct{})

	fr := &fakeRemote{
		loginEnterCh: make(chan struct{}, 1),
		onLogin: func(_ context.Context, _, _ string) error {
			<-loginBlockCh
			return nil
		},
	}

	snap := buildValidSnapshot(t, "pw", []vault.Item{
		{ID: "item-1", Name: "ShouldNotAppear", Type: vault.ItemTypeLogin},
	}, nil)

	svc := NewService(Deps{
		Remote:    fr,
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	// Start Unlock in a goroutine.
	unlockErrCh := make(chan error, 1)
	go func() {
		unlockErrCh <- svc.Unlock(context.Background(), "user@test.com", "pw")
	}()

	// Wait for Unlock to reach Login (blocked).
	<-fr.loginEnterCh

	// Call Lock while Unlock is blocked on login.
	lockErr := svc.Lock(context.Background())
	require.NoError(t, lockErr)

	// Unblock login.
	close(loginBlockCh)

	// Wait for Unlock to finish.
	unlockErr := <-unlockErrCh
	require.Error(t, unlockErr, "Unlock should return error after Lock intervened")

	// Verify service is locked and no items installed.
	svc.mu.Lock()
	require.Equal(t, auth.LockStateLocked, svc.state)
	require.Nil(t, svc.items)
	require.Nil(t, svc.index)
	svc.mu.Unlock()

	// Search should return locked error.
	_, err := svc.Search(context.Background(), "test", 10)
	require.ErrorIs(t, err, coreerrors.ErrLocked)
}

// ---------------------------------------------------------------------------
// AuthStatus tests
// ---------------------------------------------------------------------------

func TestAuthStatusUsesKeyringAndEnvelope(t *testing.T) {
	email := "user@example.com"
	ref := session.AccountRef{
		Email:     "user@example.com",
		ServerURL: "https://vault.bitwarden.com",
	}

	validBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("at"),
		RefreshToken: []byte("rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	validEnvelope := session.UnlockEnvelope{
		Version:   session.UnlockEnvelopeVersion,
		Account:   ref,
		AccountID: "acct-1",
		BootID:    "boot-123",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	t.Run("no token => unauthenticated", func(t *testing.T) {
		cs := &fakeCredentialStore{loadTokenErr: coreerrors.ErrNotFound}
		svc := NewService(Deps{
			Config:      coreconfig.Default(),
			Credentials: cs,
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.NoError(t, err)
		require.Equal(t, session.Unauthenticated, status)
	})

	t.Run("token no envelope => logged_in_locked", func(t *testing.T) {
		cs := &fakeCredentialStore{
			tokenBundle:     validBundle,
			loadEnvelopeErr: coreerrors.ErrNotFound,
		}
		svc := NewService(Deps{
			Config:      coreconfig.Default(),
			Credentials: cs,
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.NoError(t, err)
		require.Equal(t, session.LoggedInLocked, status)
	})

	t.Run("token + valid envelope => unlock_available", func(t *testing.T) {
		cs := &fakeCredentialStore{
			tokenBundle: validBundle,
			envelope:    validEnvelope,
		}
		boot := &fakeBootID{id: "boot-123"}
		svc := NewService(Deps{
			Config:      coreconfig.Default(),
			Credentials: cs,
			BootID:      boot,
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.NoError(t, err)
		require.Equal(t, session.LoggedInUnlockAvailable, status)
	})

	t.Run("keyring unavailable", func(t *testing.T) {
		cs := &fakeCredentialStore{checkAvailableErr: coreerrors.ErrUnsupported}
		svc := NewService(Deps{
			Config:      coreconfig.Default(),
			Credentials: cs,
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.Error(t, err)
		require.Equal(t, session.KeyringUnavailable, status)
		require.ErrorIs(t, err, coreerrors.ErrUnsupported)
	})

	t.Run("nil credentials => keyring_unavailable", func(t *testing.T) {
		svc := NewService(Deps{
			Config: coreconfig.Default(),
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.Error(t, err)
		require.Equal(t, session.KeyringUnavailable, status)
	})

	t.Run("bootID nil => logged_in_locked", func(t *testing.T) {
		cs := &fakeCredentialStore{
			tokenBundle: validBundle,
			envelope:    validEnvelope,
		}
		svc := NewService(Deps{
			Config:      coreconfig.Default(),
			Credentials: cs,
			BootID:      nil, // no BootID provider
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.NoError(t, err)
		require.Equal(t, session.LoggedInLocked, status)
	})

	t.Run("envelope expired => logged_in_locked", func(t *testing.T) {
		expiredEnv := validEnvelope.Clone()
		expiredEnv.ExpiresAt = time.Now().Add(-time.Hour)
		cs := &fakeCredentialStore{
			tokenBundle: validBundle,
			envelope:    expiredEnv,
		}
		boot := &fakeBootID{id: "boot-123"}
		svc := NewService(Deps{
			Config:      coreconfig.Default(),
			Credentials: cs,
			BootID:      boot,
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.NoError(t, err)
		require.Equal(t, session.LoggedInLocked, status)
	})

	t.Run("bootID changed => logged_in_locked", func(t *testing.T) {
		cs := &fakeCredentialStore{
			tokenBundle: validBundle,
			envelope:    validEnvelope,
		}
		boot := &fakeBootID{id: "boot-456"} // different from envelope's boot-123
		svc := NewService(Deps{
			Config:      coreconfig.Default(),
			Credentials: cs,
			BootID:      boot,
		})

		status, err := svc.AuthStatus(context.Background(), email)
		require.NoError(t, err)
		require.Equal(t, session.LoggedInLocked, status)
	})
}

func TestAuthStatusEffectiveServerURL(t *testing.T) {
	t.Run("default US", func(t *testing.T) {
		cs := &fakeCredentialStore{loadTokenErr: coreerrors.ErrNotFound}
		svc := NewService(Deps{Config: coreconfig.Default(), Credentials: cs})

		status, err := svc.AuthStatus(context.Background(), "user@example.com")
		require.NoError(t, err)
		require.Equal(t, session.Unauthenticated, status)
		require.Equal(t, 1, cs.loadTokenCalls)
	})

	t.Run("EU region", func(t *testing.T) {
		cfg := coreconfig.Default()
		cfg.Bitwarden.Region = coreconfig.RegionEU
		cs := &fakeCredentialStore{loadTokenErr: coreerrors.ErrNotFound}
		svc := NewService(Deps{Config: cfg, Credentials: cs})

		status, err := svc.AuthStatus(context.Background(), "user@example.com")
		require.NoError(t, err)
		require.Equal(t, session.Unauthenticated, status)
	})

	t.Run("self-hosted", func(t *testing.T) {
		cfg := coreconfig.Default()
		cfg.Bitwarden.Region = coreconfig.RegionSelfHosted
		cfg.Bitwarden.ServerURL = "https://bw.example.com/custom"
		cs := &fakeCredentialStore{loadTokenErr: coreerrors.ErrNotFound}
		svc := NewService(Deps{Config: cfg, Credentials: cs})

		status, err := svc.AuthStatus(context.Background(), "user@example.com")
		require.NoError(t, err)
		require.Equal(t, session.Unauthenticated, status)
	})
}

// ---------------------------------------------------------------------------
// ensureFreshTokens tests
// ---------------------------------------------------------------------------

func TestEnsureFreshTokensSkipsRefreshWhenFresh(t *testing.T) {
	ref := session.AccountRef{
		Email:     "user@example.com",
		ServerURL: "https://vault.bitwarden.com",
	}

	freshBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("at"),
		RefreshToken: []byte("rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(10 * time.Minute), // > 2 min
	}

	cs := &fakeCredentialStore{tokenBundle: freshBundle}
	fr := &fakeRemote{}

	svc := NewService(Deps{
		Config:      coreconfig.Default(),
		Credentials: cs,
		Remote:      fr,
	})

	bundle, err := svc.ensureFreshTokens(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, freshBundle.ExpiresAt, bundle.ExpiresAt)
	// Remote should not have been called.
	require.Equal(t, int32(0), fr.refreshTokenBundleCallCnt.Load())
}

func TestEnsureFreshTokensRefreshesAndSavesNearExpiry(t *testing.T) {
	ref := session.AccountRef{
		Email:     "user@example.com",
		ServerURL: "https://vault.bitwarden.com",
	}

	// Token expires in 1 minute (less than 2 minutes).
	nearExpiryBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("old-at"),
		RefreshToken: []byte("old-rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Minute),
	}

	updatedBundle := session.TokenBundle{
		AccountID:    "acct-1",
		AccessToken:  []byte("new-at"),
		RefreshToken: []byte("new-rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	cs := &fakeCredentialStore{tokenBundle: nearExpiryBundle}
	fr := &fakeRemote{refreshTokenBundleResult: updatedBundle}

	svc := NewService(Deps{
		Config:      coreconfig.Default(),
		Credentials: cs,
		Remote:      fr,
	})

	result, err := svc.ensureFreshTokens(context.Background(), ref)
	require.NoError(t, err)

	// Tokens should be updated.
	require.Equal(t, []byte("new-at"), result.AccessToken)
	require.Equal(t, []byte("new-rt"), result.RefreshToken)

	// Metadata (Email, ServerURL) should be preserved from original.
	require.Equal(t, ref.Email, result.Email)
	require.Equal(t, ref.ServerURL, result.ServerURL)

	// Remote should have been called once.
	require.Equal(t, int32(1), fr.refreshTokenBundleCallCnt.Load())

	// Credential store should have saved the updated bundle.
	cs.mu.Lock()
	defer cs.mu.Unlock()
	require.Equal(t, 1, cs.saveTokenCalled)
}

func TestEnsureFreshTokensDeletesInvalidRefreshToken(t *testing.T) {
	ref := session.AccountRef{
		Email:     "user@example.com",
		ServerURL: "https://vault.bitwarden.com",
	}

	nearExpiryBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("old-at"),
		RefreshToken: []byte("old-rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Minute),
	}

	cs := &fakeCredentialStore{tokenBundle: nearExpiryBundle}
	fr := &fakeRemote{refreshTokenBundleErr: coreerrors.ErrUnauthenticated}

	svc := NewService(Deps{
		Config:      coreconfig.Default(),
		Credentials: cs,
		Remote:      fr,
	})

	_, err := svc.ensureFreshTokens(context.Background(), ref)
	require.Error(t, err)
	require.True(t, errors.Is(err, coreerrors.ErrUnauthenticated))

	// Credential store should have deleted the token bundle.
	cs.mu.Lock()
	defer cs.mu.Unlock()
	require.Equal(t, 1, cs.delTokenCalls)
}

func TestEnsureFreshTokensKeepsBundleOnTransientFailure(t *testing.T) {
	ref := session.AccountRef{
		Email:     "user@example.com",
		ServerURL: "https://vault.bitwarden.com",
	}

	nearExpiryBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("old-at"),
		RefreshToken: []byte("old-rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Minute),
	}

	netErr := errors.New("network error")
	cs := &fakeCredentialStore{tokenBundle: nearExpiryBundle}
	fr := &fakeRemote{refreshTokenBundleErr: netErr}

	svc := NewService(Deps{
		Config:      coreconfig.Default(),
		Credentials: cs,
		Remote:      fr,
	})

	_, err := svc.ensureFreshTokens(context.Background(), ref)
	require.Error(t, err)

	// Credential store should NOT have deleted the token bundle.
	cs.mu.Lock()
	defer cs.mu.Unlock()
	require.Equal(t, 0, cs.delTokenCalls)
}

// ---------------------------------------------------------------------------
// Fake PIN envelope service
// ---------------------------------------------------------------------------

type fakePINEnvelope struct {
	mu sync.Mutex

	createCallCnt int
	material      session.UnlockMaterial
	ref           session.AccountRef
	pin           string
	bootID        string

	result    session.UnlockEnvelope
	createErr error

	// Open tracking
	openCallCnt  int
	openRef      session.AccountRef
	openEnvelope session.UnlockEnvelope
	openPin      string
	openBootID   string
	openMaterial session.UnlockMaterial
	openUpdated  session.UnlockEnvelope
	openErr      error
}

func (pe *fakePINEnvelope) Create(_ context.Context, ref session.AccountRef, material session.UnlockMaterial, pin string, bootID string) (session.UnlockEnvelope, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.createCallCnt++
	pe.ref = ref
	pe.material = material
	pe.pin = pin
	pe.bootID = bootID
	return pe.result, pe.createErr
}

func (pe *fakePINEnvelope) Open(_ context.Context, ref session.AccountRef, envelope session.UnlockEnvelope, pin string, bootID string) (session.UnlockMaterial, session.UnlockEnvelope, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.openCallCnt++
	pe.openRef = ref
	pe.openEnvelope = envelope
	pe.openPin = pin
	pe.openBootID = bootID
	return pe.openMaterial, pe.openUpdated, pe.openErr
}

// ---------------------------------------------------------------------------
// Login tests
// ---------------------------------------------------------------------------

func TestLoginStoresTokenBundleAndPINEnvelope(t *testing.T) {
	email := "user@example.com"
	password := "master-password"
	pin := "1234"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-abc-123"

	fr := &fakeRemote{
		exportMaterial: session.UnlockMaterial{
			UserKey: []byte("user-key-bytes"),
		},
		exportTokens: session.TokenBundle{
			AccountID:    "acct-1",
			AccessToken:  []byte("access-token"),
			RefreshToken: []byte("refresh-token"),
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}

	cs := &fakeCredentialStore{}
	pe := &fakePINEnvelope{
		result: session.UnlockEnvelope{
			Version: session.UnlockEnvelopeVersion,
			BootID:  bootID,
			Salt:    []byte("salt"),
		},
	}
	boot := &fakeBootID{id: bootID}

	// Use a cache that returns os.ErrNotExist so cache load is skipped.
	fakCache := &fakeCache{loadErr: os.ErrNotExist}

	svc := NewService(Deps{
		Remote:      fr,
		Cache:       fakCache,
		SecretBox:   &fakeSecretBox{},
		Credentials: cs,
		BootID:      boot,
		PINEnvelope: pe,
		Config:      coreconfig.Default(),
	})

	input := auth.LoginInput{
		Email:    email,
		Password: password,
		PIN:      pin,
	}

	err := svc.Login(context.Background(), input)
	require.NoError(t, err)

	// checkCredentialsAvailable should have been called.
	cs.mu.Lock()
	require.Equal(t, 1, cs.checkAvailableCalls)
	cs.mu.Unlock()

	// Remote login should be called exactly once.
	fr.mu.Lock()
	require.True(t, fr.loginCalled, "remote Login should be called")
	fr.mu.Unlock()

	// ExportSession should be called once.
	require.Equal(t, int32(1), fr.exportCallCnt.Load())

	// Token bundle should be saved under email + server.
	cs.mu.Lock()
	require.Equal(t, 1, cs.saveTokenCalled)
	require.Equal(t, 1, cs.saveEnvCalled)
	cs.mu.Unlock()

	// PIN envelope should have been created with correct material.
	pe.mu.Lock()
	require.Equal(t, 1, pe.createCallCnt)
	require.Equal(t, ref, pe.ref)
	require.Equal(t, pin, pe.pin)
	require.Equal(t, bootID, pe.bootID)
	require.Equal(t, []byte("user-key-bytes"), pe.material.UserKey)
	// CacheKey from unlock (first run with no cache) should be non-empty.
	require.NotEmpty(t, pe.material.CacheKey)
	pe.mu.Unlock()

	// Token bundle metadata should be filled on saved bundle.
	cs.mu.Lock()
	savedTK := cs.savedTokenBundle
	cs.mu.Unlock()
	require.Equal(t, ref.Email, savedTK.Email)
	require.Equal(t, ref.ServerURL, savedTK.ServerURL)
	require.False(t, savedTK.UpdatedAt.IsZero())
}

func TestLoginRequiresPINBeforeRemoteLogin(t *testing.T) {
	fr := &fakeRemote{}
	cs := &fakeCredentialStore{}
	pe := &fakePINEnvelope{
		result: session.UnlockEnvelope{Version: session.UnlockEnvelopeVersion},
	}
	boot := &fakeBootID{id: "boot-xyz"}

	fakCache := &fakeCache{loadErr: os.ErrNotExist}

	svc := NewService(Deps{
		Remote:      fr,
		Cache:       fakCache,
		SecretBox:   &fakeSecretBox{},
		Credentials: cs,
		BootID:      boot,
		PINEnvelope: pe,
		Config:      coreconfig.Default(),
	})

	// Missing PIN should return a validation error before any remote login.
	input := auth.LoginInput{
		Email:    "user@example.com",
		Password: "master-password",
		PIN:      "",
	}

	err := svc.Login(context.Background(), input)
	require.Error(t, err)
	require.Contains(t, err.Error(), "PIN is required")

	// Remote login should NOT have been called.
	fr.mu.Lock()
	require.False(t, fr.loginCalled, "remote Login should not be called when PIN is missing")
	fr.mu.Unlock()

	// Whitespace-only PIN should also be rejected.
	input.PIN = "  "
	err = svc.Login(context.Background(), input)
	require.Error(t, err)
	require.Contains(t, err.Error(), "PIN is required")

	fr.mu.Lock()
	require.False(t, fr.loginCalled)
	fr.mu.Unlock()
}

// realClock is a minimal out.Clock that delegates to time.Now.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ---------------------------------------------------------------------------
// UnlockWithPIN tests
// ---------------------------------------------------------------------------

func TestUnlockWithPINRestoresSessionAndInstallsCacheKey(t *testing.T) {
	email := "user@example.com"
	pin := "1234"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-abc"

	validBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("at"),
		RefreshToken: []byte("rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	envelope := session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		AccountID:      "acct-1",
		BootID:         bootID,
		ExpiresAt:      time.Now().Add(time.Hour),
		FailedAttempts: 2,
		PINMaxFailures: 5,
		BackoffUntil:   time.Now().Add(-time.Hour), // past backoff
	}

	material := session.UnlockMaterial{
		CacheKey: []byte("cache-key-from-material"),
		UserKey:  []byte("user-key"),
	}

	// Reset envelope after successful open.
	resetEnvelope := envelope.Clone()
	resetEnvelope.FailedAttempts = 0
	resetEnvelope.BackoffUntil = time.Time{}

	cs := &fakeCredentialStore{
		tokenBundle: validBundle,
		envelope:    envelope,
	}
	pe := &fakePINEnvelope{
		openMaterial: material,
		openUpdated:  resetEnvelope,
		openErr:      nil,
	}
	boot := &fakeBootID{id: bootID}
	fr := &fakeRemote{}

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email

	svc := NewService(Deps{
		Config:      cfg,
		Remote:      fr,
		Credentials: cs,
		BootID:      boot,
		PINEnvelope: pe,
	})

	err := svc.UnlockWithPIN(context.Background(), email, pin)
	require.NoError(t, err)

	// Verify PIN envelope was opened with correct parameters.
	pe.mu.Lock()
	require.Equal(t, 1, pe.openCallCnt)
	require.Equal(t, pin, pe.openPin)
	require.Equal(t, bootID, pe.openBootID)
	pe.mu.Unlock()

	// RestoreSession should be called with material and tokens.
	fr.mu.Lock()
	require.Equal(t, 1, fr.restoreCallCnt)
	require.Equal(t, []byte("cache-key-from-material"), fr.restoreMaterial.CacheKey)
	require.Equal(t, []byte("user-key"), fr.restoreMaterial.UserKey)
	require.Equal(t, []byte("at"), fr.restoreTokens.AccessToken)
	fr.mu.Unlock()

	// State should be unlocked.
	svc.mu.Lock()
	require.Equal(t, auth.LockStateUnlocked, svc.state)
	require.Equal(t, []byte("cache-key-from-material"), svc.cacheKey)
	svc.mu.Unlock()

	// Search should not return locked error.
	_, err = svc.Search(context.Background(), "test", 10)
	require.NoError(t, err)

	// Envelope should have been saved with reset counters.
	cs.mu.Lock()
	require.True(t, cs.saveEnvCalled >= 1, "expected envelope save")
	require.Equal(t, 0, cs.savedUnlockEnvelope.FailedAttempts)
	require.True(t, cs.savedUnlockEnvelope.BackoffUntil.IsZero())
	cs.mu.Unlock()
}

func TestUnlockWithPINWrongPINRecordsFailure(t *testing.T) {
	email := "user@example.com"
	pin := "wrong-pin"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-abc"

	validBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("at"),
		RefreshToken: []byte("rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	envelope := session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		AccountID:      "acct-1",
		BootID:         bootID,
		ExpiresAt:      time.Now().Add(time.Hour),
		FailedAttempts: 0,
		PINMaxFailures: 5,
	}

	// Open returns updated envelope with 1 failure and error.
	updatedEnvelope := envelope.Clone()
	updatedEnvelope.FailedAttempts = 1
	updatedEnvelope.BackoffUntil = time.Now().Add(time.Second)

	cs := &fakeCredentialStore{
		tokenBundle: validBundle,
		envelope:    envelope,
	}
	pe := &fakePINEnvelope{
		openUpdated: updatedEnvelope,
		openErr:     fmt.Errorf("pinenvelope: invalid pin"),
	}
	boot := &fakeBootID{id: bootID}
	fr := &fakeRemote{}

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email

	svc := NewService(Deps{
		Config:      cfg,
		Remote:      fr,
		Credentials: cs,
		BootID:      boot,
		PINEnvelope: pe,
	})

	err := svc.UnlockWithPIN(context.Background(), email, pin)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid pin")

	// State should remain locked.
	svc.mu.Lock()
	require.Equal(t, auth.LockStateLocked, svc.state)
	svc.mu.Unlock()

	// Search should return locked error.
	_, searchErr := svc.Search(context.Background(), "test", 10)
	require.ErrorIs(t, searchErr, coreerrors.ErrLocked)

	// RestoreSession must NOT be called.
	fr.mu.Lock()
	require.Equal(t, 0, fr.restoreCallCnt)
	fr.mu.Unlock()

	// Updated envelope should be saved (failure counters incremented).
	cs.mu.Lock()
	require.True(t, cs.saveEnvCalled >= 1, "expected envelope save after failed PIN")
	require.Equal(t, 1, cs.savedUnlockEnvelope.FailedAttempts)
	require.False(t, cs.savedUnlockEnvelope.BackoffUntil.IsZero())
	// Envelope should NOT be deleted.
	require.Equal(t, 0, cs.delEnvCalls)
	cs.mu.Unlock()
}

func TestUnlockWithPINDeletesEnvelopeAfterMaxFailures(t *testing.T) {
	email := "user@example.com"
	pin := "wrong-pin"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-abc"

	validBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("at"),
		RefreshToken: []byte("rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	envelope := session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		AccountID:      "acct-1",
		BootID:         bootID,
		ExpiresAt:      time.Now().Add(time.Hour),
		FailedAttempts: 4, // one more will reach max (5)
		PINMaxFailures: 5,
	}

	// Open returns updated envelope with 5 failures → ShouldDeleteAfterFailures.
	updatedEnvelope := envelope.Clone()
	updatedEnvelope.FailedAttempts = 5
	updatedEnvelope.BackoffUntil = time.Now().Add(time.Minute)

	cs := &fakeCredentialStore{
		tokenBundle: validBundle,
		envelope:    envelope,
	}
	pe := &fakePINEnvelope{
		openUpdated: updatedEnvelope,
		openErr:     fmt.Errorf("pinenvelope: invalid pin"),
	}
	boot := &fakeBootID{id: bootID}
	fr := &fakeRemote{}

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email

	svc := NewService(Deps{
		Config:      cfg,
		Remote:      fr,
		Credentials: cs,
		BootID:      boot,
		PINEnvelope: pe,
	})

	err := svc.UnlockWithPIN(context.Background(), email, pin)
	require.Error(t, err)

	// RestoreSession must NOT be called.
	fr.mu.Lock()
	require.Equal(t, 0, fr.restoreCallCnt)
	fr.mu.Unlock()

	// Envelope should be deleted (max failures reached).
	cs.mu.Lock()
	require.Equal(t, 1, cs.delEnvCalls, "envelope should be deleted after max failures")
	// Should NOT be saved.
	require.Equal(t, 0, cs.saveEnvCalled)
	cs.mu.Unlock()
}

func TestUnlockWithPINExpiredOrBootChangedDoesNotRestore(t *testing.T) {
	email := "user@example.com"
	pin := "1234"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-current"

	validBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("at"),
		RefreshToken: []byte("rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	envelope := session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		AccountID:      "acct-1",
		BootID:         "boot-old",                 // different from current boot
		ExpiresAt:      time.Now().Add(-time.Hour), // already expired
		FailedAttempts: 0,
		PINMaxFailures: 5,
	}

	cs := &fakeCredentialStore{
		tokenBundle: validBundle,
		envelope:    envelope,
	}
	// Open returns same envelope (unchanged counters) with error.
	pe := &fakePINEnvelope{
		openUpdated: envelope.Clone(),
		openErr:     fmt.Errorf("pinenvelope: unlock envelope expired or boot changed"),
	}
	boot := &fakeBootID{id: bootID}
	fr := &fakeRemote{}

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email

	svc := NewService(Deps{
		Config:      cfg,
		Remote:      fr,
		Credentials: cs,
		BootID:      boot,
		PINEnvelope: pe,
	})

	err := svc.UnlockWithPIN(context.Background(), email, pin)
	require.Error(t, err)

	// RestoreSession must NOT be called.
	fr.mu.Lock()
	require.Equal(t, 0, fr.restoreCallCnt)
	fr.mu.Unlock()

	// Envelope should NOT be saved or deleted (counters unchanged).
	cs.mu.Lock()
	require.Equal(t, 0, cs.saveEnvCalled)
	require.Equal(t, 0, cs.delEnvCalls)
	cs.mu.Unlock()
}

func TestUnlockWithPINRefreshesNearExpiryBeforeRestore(t *testing.T) {
	email := "user@example.com"
	pin := "1234"
	ref := session.AccountRef{Email: email, ServerURL: "https://vault.bitwarden.com"}
	bootID := "boot-abc"

	// Near-expiry token (within 2 minutes).
	nearExpiryBundle := session.TokenBundle{
		AccountID:    "acct-1",
		Email:        ref.Email,
		ServerURL:    ref.ServerURL,
		AccessToken:  []byte("old-at"),
		RefreshToken: []byte("old-rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Minute),
	}

	refreshedBundle := session.TokenBundle{
		AccountID:    "acct-1",
		AccessToken:  []byte("new-at"),
		RefreshToken: []byte("new-rt"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	envelope := session.UnlockEnvelope{
		Version:        session.UnlockEnvelopeVersion,
		Account:        ref,
		AccountID:      "acct-1",
		BootID:         bootID,
		ExpiresAt:      time.Now().Add(time.Hour),
		FailedAttempts: 0,
		PINMaxFailures: 5,
	}

	material := session.UnlockMaterial{
		CacheKey: []byte("cache-key"),
		UserKey:  []byte("user-key"),
	}

	cs := &fakeCredentialStore{
		tokenBundle: nearExpiryBundle,
		envelope:    envelope,
	}
	pe := &fakePINEnvelope{
		openMaterial: material,
		openUpdated:  envelope.Clone(),
		openErr:      nil,
	}
	boot := &fakeBootID{id: bootID}
	fr := &fakeRemote{refreshTokenBundleResult: refreshedBundle}

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email

	svc := NewService(Deps{
		Config:      cfg,
		Remote:      fr,
		Credentials: cs,
		BootID:      boot,
		PINEnvelope: pe,
	})

	err := svc.UnlockWithPIN(context.Background(), email, pin)
	require.NoError(t, err)

	// Refresh should have been called.
	require.Equal(t, int32(1), fr.refreshTokenBundleCallCnt.Load())

	// RestoreSession should receive the refreshed token.
	fr.mu.Lock()
	require.Equal(t, 1, fr.restoreCallCnt)
	require.Equal(t, []byte("new-at"), fr.restoreTokens.AccessToken)
	require.Equal(t, []byte("new-rt"), fr.restoreTokens.RefreshToken)
	fr.mu.Unlock()

	// Token bundle should have been saved after refresh.
	cs.mu.Lock()
	require.True(t, cs.saveTokenCalled >= 1)
	cs.mu.Unlock()
}

func TestUnlockWithPINRequiresLockedState(t *testing.T) {
	email := "user@example.com"
	pin := "1234"

	cfg := coreconfig.Default()
	cfg.Bitwarden.Email = email

	// Create a service that is already unlocked, with deps that pass initial checks.
	svc := NewService(Deps{
		Config:      cfg,
		Credentials: &fakeCredentialStore{},
		Remote:      &fakeRemote{},
		PINEnvelope: &fakePINEnvelope{},
		BootID:      &fakeBootID{id: "boot-1"},
	})
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.mu.Unlock()

	err := svc.UnlockWithPIN(context.Background(), email, pin)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot unlock in state")
}

func TestUnlockWithPINRequiresDeps(t *testing.T) {
	email := "user@example.com"
	pin := "1234"

	t.Run("nil credentials", func(t *testing.T) {
		svc := NewService(Deps{})
		err := svc.UnlockWithPIN(context.Background(), email, pin)
		require.Error(t, err)
		require.ErrorIs(t, err, coreerrors.ErrUnsupported)
	})

	t.Run("nil Remote", func(t *testing.T) {
		svc := NewService(Deps{
			Credentials: &fakeCredentialStore{},
		})
		err := svc.UnlockWithPIN(context.Background(), email, pin)
		require.Error(t, err)
		require.ErrorIs(t, err, coreerrors.ErrUnsupported)
	})

	t.Run("nil PINEnvelope", func(t *testing.T) {
		svc := NewService(Deps{
			Credentials: &fakeCredentialStore{},
			Remote:      &fakeRemote{},
		})
		err := svc.UnlockWithPIN(context.Background(), email, pin)
		require.Error(t, err)
		require.ErrorIs(t, err, coreerrors.ErrUnsupported)
	})

	t.Run("nil BootID", func(t *testing.T) {
		svc := NewService(Deps{
			Credentials: &fakeCredentialStore{},
			Remote:      &fakeRemote{},
			PINEnvelope: &fakePINEnvelope{},
		})
		err := svc.UnlockWithPIN(context.Background(), email, pin)
		require.Error(t, err)
		require.ErrorIs(t, err, coreerrors.ErrUnsupported)
	})
}

// ---------------------------------------------------------------------------
// Bounded plaintext vault read tests
// ---------------------------------------------------------------------------

// buildCacheSnapshotWithKey creates a cache.Snapshot containing items and
// folders as a PlainSnapshot, "encrypted" (via SecretBox) with the given key.
// Uses fakeSecretBox so encryption is identity; the key is recorded but
// decrypt always succeeds with any matching-length key.
func buildCacheSnapshotWithKey(t *testing.T, key []byte, items []vault.Item, folders []vault.Folder) cache.Snapshot {
	t.Helper()

	itemsJSON, err := json.Marshal(items)
	require.NoError(t, err)

	foldersJSON, err := json.Marshal(folders)
	require.NoError(t, err)

	plain := cache.PlainSnapshot{
		AccountHash: "test-account-hash",
		SavedAt:     time.Now(),
		ItemsJSON:   itemsJSON,
		FoldersJSON: foldersJSON,
	}

	plainJSON, err := json.Marshal(plain)
	require.NoError(t, err)

	box := &fakeSecretBox{}
	ciphertext, err := box.Seal(plainJSON, key)
	require.NoError(t, err)

	return cache.Snapshot{
		Version:         cache.Version,
		AccountHash:     "test-account-hash",
		SavedAt:         time.Now(),
		VaultCiphertext: ciphertext,
	}
}

func TestSearchDoesNotLeavePlaintextItemsResidentAfterOperation(t *testing.T) {
	cacheKey := []byte("test-cache-key-32-bytes-long!")
	gitItem := vault.Item{
		ID:    "item-1",
		Name:  "GitHub",
		Type:  vault.ItemTypeLogin,
		Login: &vault.Login{Username: "user"},
	}

	snap := buildCacheSnapshotWithKey(t, cacheKey, []vault.Item{gitItem}, nil)

	svc := NewService(Deps{
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	// Simulate PIN unlock: state unlocked, cache key set, no resident items/index.
	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], cacheKey...)
	svc.mu.Unlock()

	// Search should find the item via cache.
	results, err := svc.Search(context.Background(), "git", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "GitHub", results[0].Item.Name)

	// After operation, no plaintext items/index should be resident.
	svc.mu.Lock()
	require.Nil(t, svc.items, "s.items should be nil after cache-only search")
	require.Nil(t, svc.index, "s.index should be nil after cache-only search")
	svc.mu.Unlock()
}

func TestGetDoesNotLeavePlaintextItemsResidentAfterOperation(t *testing.T) {
	cacheKey := []byte("test-cache-key-32-bytes-long!")
	item1 := vault.Item{
		ID:   "item-1",
		Name: "GitHub",
		Type: vault.ItemTypeLogin,
	}
	item2 := vault.Item{
		ID:   "item-2",
		Name: "GitLab",
		Type: vault.ItemTypeLogin,
	}

	snap := buildCacheSnapshotWithKey(t, cacheKey, []vault.Item{item1, item2}, nil)

	svc := NewService(Deps{
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], cacheKey...)
	svc.mu.Unlock()

	// Get existing item.
	item, err := svc.Get(context.Background(), "item-1")
	require.NoError(t, err)
	require.Equal(t, "GitHub", item.Name)

	// Get non-existing item.
	_, err = svc.Get(context.Background(), "item-999")
	require.ErrorIs(t, err, coreerrors.ErrNotFound)

	// After operation, no plaintext items/index should be resident.
	svc.mu.Lock()
	require.Nil(t, svc.items, "s.items should be nil after cache-only Get")
	require.Nil(t, svc.index, "s.index should be nil after cache-only Get")
	svc.mu.Unlock()
}

func TestItemsDoesNotLeavePlaintextItemsResidentAfterOperation(t *testing.T) {
	cacheKey := []byte("test-cache-key-32-bytes-long!")
	gitItem := vault.Item{
		ID:   "item-1",
		Name: "GitHub",
		Type: vault.ItemTypeLogin,
	}

	snap := buildCacheSnapshotWithKey(t, cacheKey, []vault.Item{gitItem}, nil)

	svc := NewService(Deps{
		Cache:     &fakeCache{data: &snap},
		SecretBox: &fakeSecretBox{},
	})

	svc.mu.Lock()
	svc.state = auth.LockStateUnlocked
	svc.cacheKey = append(svc.cacheKey[:0], cacheKey...)
	svc.mu.Unlock()

	items, err := svc.Items(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "GitHub", items[0].Name)

	// After operation, no plaintext items/index should be resident.
	svc.mu.Lock()
	require.Nil(t, svc.items, "s.items should be nil after cache-only Items")
	require.Nil(t, svc.index, "s.index should be nil after cache-only Items")
	svc.mu.Unlock()
}
