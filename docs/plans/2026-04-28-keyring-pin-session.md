# Keyring PIN Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan phase-by-phase. Each phase contains sub-tasks with checkbox steps (`- [ ]`) for tracking. Review gates happen at the end of each phase, not after every sub-task.

**Goal:** Replace placeholder `BW_SESSION` auth with Linux Secret Service token storage, mandatory local PIN unlock envelopes, refreshable Bitwarden server sessions, and bounded vault plaintext lifetime.

**Architecture:** Add a minimal public session/token surface to `bitwarden-go-sdk`: export/restore unlocked material and refresh token bundles without exposing internal packages. In `gtk4-layershell-bitwarden`, keep session policy in app/core ports, use a Secret Service adapter keyed by normalized email + server identity, wrap local unlock material with a mandatory PIN, and make CLI/overlay flows consume explicit auth status rather than process-local environment variables.

**Tech Stack:** Go 1.26, Cobra/Viper, `github.com/zalando/go-keyring`, XChaCha20-Poly1305, Argon2id, local `github.com/bnema/bitwarden-go-sdk` replace, GTK4 layer-shell.

---

## Senior review revisions included

A senior review found blockers in the first draft. This plan fixes them as follows:

- Keyring lookup keys use normalized email + server URL only. `AccountID` remains payload metadata because startup often does not know it yet.
- `CredentialStore.CheckAvailable(ctx)` is required and called before prompting for Bitwarden credentials, PIN, or overlay unlock.
- CLI `login` is a single app-service call. It does not first call `UnlockWithTwoFactor` and then call `Login` again.
- Token refresh is a concrete SDK/app API with tests for save-back, invalid refresh deletion, and transient failure preservation.
- The spec now explicitly allows the PIN envelope to wrap both cache key and Bitwarden user key, with the security trade-off documented.
- PIN failed-attempt backoff and max-failure envelope deletion are implemented, not only represented as fields.
- Overlay startup uses an explicit auth-status API to choose onboarding, PIN prompt, master-password prompt, or keyring error.
- Bounded plaintext work uses the current app signature: `Search(ctx, query string, limit int) ([]vault.ScoredItem, error)`.

---

## File structure

### SDK repository: `/home/brice/dev/projects/bitwarden-go-sdk`

- Modify `bitwarden/types.go`: public `TokenSet`, `SessionMaterial`, `RefreshResult`.
- Add `bitwarden/token_store.go`: public `TokenStore` adapter to internal `ports.TokenStore`.
- Modify `bitwarden/options.go`: exported `WithTokenStore` for SDK-owned token persistence. This remains account-ID keyed because it is internal SDK state, not the app keyring lookup scheme.
- Modify `bitwarden/auth.go`: `ExportSession`, `RestoreSession`, `RefreshSession`.
- Modify `bitwarden/client.go`: wire token-store adapter and refresh coordinator.
- Tests in `bitwarden/session_test.go`, `bitwarden/client_test.go`, `bitwarden/auth_test.go`.

### App repository: `/home/brice/dev/projects/gtk4-layershell-bitwarden`

- Add `internal/core/session/types.go`: `AccountRef`, `TokenBundle`, `UnlockMaterial`, `UnlockEnvelope`, `AuthStatus`.
- Add `internal/core/session/envelope.go`: expiry, boot-id, account validation, failed PIN attempt policy.
- Add `internal/ports/out/credentials.go`: `CredentialStore`, `BootIDProvider`, `PINEnvelopeService`.
- Modify `internal/ports/out/remote.go`: session export/restore and token refresh methods.
- Modify `internal/ports/in/app.go`: login, PIN unlock, auth status APIs.
- Add `internal/adapters/secrets/keyring/store.go`: Secret Service adapter using `zalando/go-keyring`.
- Add `internal/adapters/session/bootid/bootid_linux.go`: reads `/proc/sys/kernel/random/boot_id`.
- Add `internal/adapters/session/pinenvelope/service.go`: Argon2id + XChaCha20-Poly1305 envelope service.
- Modify `internal/app/service.go`: fail-fast keyring checks, token storage/refresh, mandatory PIN, lock/logout, auth status, bounded search state.
- Modify `internal/adapters/cli/cobra/auth.go` and `root.go`: split login/unlock flows, remove `BW_SESSION`, compose dependencies.
- Modify `internal/adapters/gui/omnibox/*`: PIN prompt mode from auth status.
- Modify `README.md`: document Secret Service + PIN sessions.

---

## Phase 1: SDK public session/token/refresh surface

**Goal:** The app can persist SDK tokens externally, restore unlocked SDK state from wrapped material, and refresh expired tokens through a public SDK method.

**Files:**
- Create: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/token_store.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/types.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/options.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/auth.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/client.go`
- Test: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/session_test.go`
- Test: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/client_test.go`

#### Sub-task 1: Add public token/session types

- [ ] **Step 1: Write failing clone/zeroization tests**

Add to `bitwarden/session_test.go`:

```go
func TestSessionMaterialCloneDoesNotShareSecretSlices(t *testing.T) {
	orig := SessionMaterial{
		AccountID: "account-1",
		UserKey:   []byte("user-key"),
		Tokens: TokenSet{
			AccountID:    "account-1",
			AccessToken:  []byte("access"),
			RefreshToken: []byte("refresh"),
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}
	clone := orig.Clone()
	orig.UserKey[0] = 'X'
	orig.Tokens.AccessToken[0] = 'Y'
	orig.Tokens.RefreshToken[0] = 'Z'
	require.Equal(t, []byte("user-key"), clone.UserKey)
	require.Equal(t, []byte("access"), clone.Tokens.AccessToken)
	require.Equal(t, []byte("refresh"), clone.Tokens.RefreshToken)
}

func TestSessionMaterialCloseZeroesSecrets(t *testing.T) {
	material := SessionMaterial{UserKey: []byte("user-key"), Tokens: TokenSet{AccessToken: []byte("access"), RefreshToken: []byte("refresh")}}
	user := material.UserKey
	access := material.Tokens.AccessToken
	refresh := material.Tokens.RefreshToken
	material.Close()
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, user)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0}, access)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0}, refresh)
}
```

Run:

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk go test ./bitwarden -run 'TestSessionMaterialCloneDoesNotShareSecretSlices|TestSessionMaterialCloseZeroesSecrets'
```

Expected: FAIL because public types do not exist.

- [ ] **Step 2: Implement public types**

Add to `bitwarden/types.go`:

```go
type TokenSet struct {
	AccountID    string
	AccessToken  []byte
	RefreshToken []byte
	TokenType    string
	ExpiresAt    time.Time
}

func (t TokenSet) Clone() TokenSet {
	return TokenSet{AccountID: t.AccountID, AccessToken: append([]byte(nil), t.AccessToken...), RefreshToken: append([]byte(nil), t.RefreshToken...), TokenType: t.TokenType, ExpiresAt: t.ExpiresAt}
}

func (t *TokenSet) Close() {
	if t == nil { return }
	for i := range t.AccessToken { t.AccessToken[i] = 0 }
	for i := range t.RefreshToken { t.RefreshToken[i] = 0 }
	t.AccessToken = nil
	t.RefreshToken = nil
}

type SessionMaterial struct {
	AccountID string
	UserKey   []byte
	Tokens    TokenSet
}

func (s SessionMaterial) Clone() SessionMaterial {
	return SessionMaterial{AccountID: s.AccountID, UserKey: append([]byte(nil), s.UserKey...), Tokens: s.Tokens.Clone()}
}

func (s *SessionMaterial) Close() {
	if s == nil { return }
	for i := range s.UserKey { s.UserKey[i] = 0 }
	s.UserKey = nil
	s.Tokens.Close()
}

type RefreshResult struct {
	Tokens TokenSet
}
```

Add `import "time"` to `types.go`.

Run:

```bash
rtk gofmt -w bitwarden/types.go bitwarden/session_test.go
rtk go test ./bitwarden -run 'TestSessionMaterialCloneDoesNotShareSecretSlices|TestSessionMaterialCloseZeroesSecrets'
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
rtk git add bitwarden/types.go bitwarden/session_test.go
rtk git commit -m "feat: add public session material types"
```

#### Sub-task 2: Add public token store injection

- [ ] **Step 1: Write failing token-store test**

Add to `bitwarden/client_test.go`:

```go
type publicTokenStoreStub struct { saved TokenSet; loaded TokenSet; deleted string }
func (s *publicTokenStoreStub) SaveTokens(_ context.Context, tokens TokenSet) error { s.saved = tokens.Clone(); s.loaded = tokens.Clone(); return nil }
func (s *publicTokenStoreStub) LoadTokens(_ context.Context, accountID string) (TokenSet, error) { if s.loaded.AccountID != accountID { return TokenSet{}, ErrNotFound }; return s.loaded.Clone(), nil }
func (s *publicTokenStoreStub) DeleteTokens(_ context.Context, accountID string) error { s.deleted = accountID; return nil }

func TestWithTokenStoreSavesLoginTokens(t *testing.T) {
	identity, crypto, _ := publicAuthDeps(t)
	store := &publicTokenStoreStub{}
	masterKey := ports.MasterKey{Bytes: []byte("master")}
	userKey := ports.UserKey{Bytes: []byte("user")}
	tokens := ports.TokenSet{AccountID: "account-1", AccessToken: ports.NewSecretBytes([]byte("access")), RefreshToken: ports.NewSecretBytes([]byte("refresh")), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-1", EncryptedUserKey: "enc-user"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user"}).Return(userKey, nil)
	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), WithTokenStore(store))
	require.NoError(t, err)
	require.NoError(t, client.Login(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"}))
	require.Equal(t, "account-1", store.saved.AccountID)
	require.Equal(t, []byte("access"), store.saved.AccessToken)
	require.Equal(t, []byte("refresh"), store.saved.RefreshToken)
}
```

Run `rtk go test ./bitwarden -run TestWithTokenStoreSavesLoginTokens`. Expected: FAIL.

- [ ] **Step 2: Implement `TokenStore` and `WithTokenStore`**

Create `bitwarden/token_store.go`:

```go
package bitwarden

import (
	"context"
	"errors"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

var ErrNotFound = errors.New("bitwarden: tokens not found")

type TokenStore interface {
	SaveTokens(ctx context.Context, tokens TokenSet) error
	LoadTokens(ctx context.Context, accountID string) (TokenSet, error)
	DeleteTokens(ctx context.Context, accountID string) error
}

type publicTokenStoreAdapter struct { store TokenStore }

func (a publicTokenStoreAdapter) SaveTokens(ctx context.Context, tokens ports.TokenSet) error { return a.store.SaveTokens(ctx, publicTokenSet(tokens)) }
func (a publicTokenStoreAdapter) LoadTokens(ctx context.Context, accountID string) (ports.TokenSet, error) { tokens, err := a.store.LoadTokens(ctx, accountID); if err != nil { return ports.TokenSet{}, err }; return internalTokenSet(tokens), nil }
func (a publicTokenStoreAdapter) DeleteTokens(ctx context.Context, accountID string) error { return a.store.DeleteTokens(ctx, accountID) }

func internalTokenSet(tokens TokenSet) ports.TokenSet { return ports.TokenSet{AccountID: tokens.AccountID, AccessToken: ports.NewSecretBytes(tokens.AccessToken), RefreshToken: ports.NewSecretBytes(tokens.RefreshToken), TokenType: tokens.TokenType, ExpiresAt: tokens.ExpiresAt} }
func publicTokenSet(tokens ports.TokenSet) TokenSet { return TokenSet{AccountID: tokens.AccountID, AccessToken: append([]byte(nil), tokens.AccessToken.Bytes()...), RefreshToken: append([]byte(nil), tokens.RefreshToken.Bytes()...), TokenType: tokens.TokenType, ExpiresAt: tokens.ExpiresAt} }
```

Add to `bitwarden/options.go`:

```go
func WithTokenStore(tokens TokenStore) Option {
	return func(cfg *clientConfig) error {
		if tokens != nil { cfg.tokens = publicTokenStoreAdapter{store: tokens} }
		return nil
	}
}
```

Run:

```bash
rtk gofmt -w bitwarden
rtk go test ./bitwarden -run TestWithTokenStoreSavesLoginTokens
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
rtk git add bitwarden/token_store.go bitwarden/options.go bitwarden/client_test.go
rtk git commit -m "feat: expose token store injection"
```

#### Sub-task 3: Add export, restore, and refresh methods

- [ ] **Step 1: Write failing tests**

Add to `bitwarden/session_test.go`:

```go
func TestExportSessionReturnsUnlockedMaterial(t *testing.T) {
	client := loggedInClientForSessionTests(t, nil)
	material, err := client.ExportSession(context.Background())
	require.NoError(t, err)
	require.Equal(t, "account-1", material.AccountID)
	require.NotEmpty(t, material.UserKey)
	require.NotEmpty(t, material.Tokens.AccessToken)
}

func TestRestoreSessionUnlocksClient(t *testing.T) {
	client, err := NewClient()
	require.NoError(t, err)
	material := SessionMaterial{AccountID: "account-1", UserKey: []byte("user-key"), Tokens: TokenSet{AccountID: "account-1", AccessToken: []byte("access"), RefreshToken: []byte("refresh"), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	require.NoError(t, client.RestoreSession(context.Background(), material))
	require.False(t, client.IsLocked())
}

func TestRefreshSessionSavesNewTokens(t *testing.T) {
	store := &publicTokenStoreStub{loaded: TokenSet{AccountID: "account-1", RefreshToken: []byte("old-refresh"), TokenType: "Bearer"}}
	identity := mocks.NewMockIdentityClient(t)
	identity.EXPECT().Refresh(mock.Anything, mock.Anything).Return(ports.TokenResponse{Tokens: ports.TokenSet{AccountID: "account-1", AccessToken: ports.NewSecretBytes([]byte("new-access")), RefreshToken: ports.NewSecretBytes([]byte("new-refresh")), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}}, nil)
	client, err := NewClient(withIdentityClient(identity), WithTokenStore(store))
	require.NoError(t, err)
	result, err := client.RefreshSession(context.Background(), "account-1")
	require.NoError(t, err)
	require.Equal(t, []byte("new-refresh"), result.Tokens.RefreshToken)
	require.Equal(t, []byte("new-refresh"), store.saved.RefreshToken)
}
```

Run:

```bash
rtk go test ./bitwarden -run 'TestExportSessionReturnsUnlockedMaterial|TestRestoreSessionUnlocksClient|TestRefreshSessionSavesNewTokens'
```

Expected: FAIL because methods are missing.

- [ ] **Step 2: Implement methods**

Add to `bitwarden/auth.go`:

```go
func (c *Client) ExportSession(ctx context.Context) (SessionMaterial, error) {
	c.mu.Lock()
	accountID := c.accountID
	userKey := c.userKey.Clone()
	c.mu.Unlock()
	if accountID == "" || c.IsLocked() { userKey.Close(); return SessionMaterial{}, &Error{Kind: ErrorKindLocked, Op: "Client.ExportSession", Message: "client is locked"} }
	tokens, err := c.tokens.LoadTokens(ctx, accountID)
	if err != nil { userKey.Close(); return SessionMaterial{}, mapCoreError(err) }
	return SessionMaterial{AccountID: accountID, UserKey: append([]byte(nil), userKey.Bytes()...), Tokens: publicTokenSet(tokens)}, nil
}

func (c *Client) RestoreSession(ctx context.Context, material SessionMaterial) error {
	if material.AccountID == "" || len(material.UserKey) == 0 { return &Error{Kind: ErrorKindValidation, Op: "Client.RestoreSession", Message: "account id and user key are required"} }
	cloned := material.Clone()
	defer cloned.Close()
	if cloned.Tokens.AccountID == "" { cloned.Tokens.AccountID = cloned.AccountID }
	if len(cloned.Tokens.AccessToken) > 0 || len(cloned.Tokens.RefreshToken) > 0 { if err := c.tokens.SaveTokens(ctx, internalTokenSet(cloned.Tokens)); err != nil { return mapCoreError(err) } }
	c.mu.Lock()
	c.userKey.Close()
	c.accountID = cloned.AccountID
	c.userKey = ports.UserKey{Bytes: append([]byte(nil), cloned.UserKey...)}
	installed := c.userKey.Clone()
	c.mu.Unlock()
	c.locked.Store(false)
	c.vaultService.SetUserKey(installed)
	c.vaultService.SetLocked(false)
	return nil
}

func (c *Client) RefreshSession(ctx context.Context, accountID string) (RefreshResult, error) {
	coord := session.NewRefreshCoordinator(session.RefreshDependencies{Identity: c.identity, Tokens: c.tokens})
	tokens, err := coord.Refresh(ctx, accountID)
	if err != nil { return RefreshResult{}, mapCoreError(err) }
	return RefreshResult{Tokens: publicTokenSet(tokens)}, nil
}
```

Add `internal/core/session` import alias if needed.

Run:

```bash
rtk gofmt -w bitwarden
rtk go test ./bitwarden -run 'TestExportSessionReturnsUnlockedMaterial|TestRestoreSessionUnlocksClient|TestRefreshSessionSavesNewTokens'
```

Expected: PASS.

- [ ] **Step 3: Full SDK validation and commit**

```bash
rtk go test ./...
rtk go test -race ./...
rtk golangci-lint run ./...
rtk git add bitwarden
rtk git commit -m "feat: export restore and refresh sessions"
```

Expected: all pass.

**Phase review checkpoint:** Ask `go-reviewer` and `senior-engineer` to review SDK public API, secret-copy behavior, and whether app/server scoping remains app-owned.

---

## Phase 2: App session domain, keyring store, boot id, and PIN envelopes

**Goal:** App has pure session types, a fail-fast Secret Service credential store keyed by email+server, and PIN envelope crypto with persisted failure policy.

**Files:**
- Create `internal/core/session/types.go`, `envelope.go`, `envelope_test.go`
- Create `internal/ports/out/credentials.go`
- Create `internal/adapters/secrets/keyring/store.go`, `store_test.go`
- Create `internal/adapters/session/bootid/bootid_linux.go`, `bootid_stub.go`
- Create `internal/adapters/session/pinenvelope/service.go`, `service_test.go`
- Modify `go.mod`, `go.sum`

#### Sub-task 1: Add domain types and validation

- [ ] **Step 1: Write tests**

Create `internal/core/session/envelope_test.go` with:

```go
func TestUnlockEnvelopeValidatesEmailServerBootAndExpiry(t *testing.T) {
	ref := AccountRef{Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	env := UnlockEnvelope{Version: UnlockEnvelopeVersion, Account: ref, AccountID: "acct", BootID: "boot-1", ExpiresAt: time.Date(2026, 4, 28, 12, 30, 0, 0, time.UTC)}
	require.NoError(t, env.Validate(ref, "boot-1", time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)))
	require.ErrorIs(t, env.Validate(ref, "boot-2", time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)), ErrBootChanged)
	require.ErrorIs(t, env.Validate(ref, "boot-1", time.Date(2026, 4, 28, 12, 31, 0, 0, time.UTC)), ErrUnlockExpired)
	require.ErrorIs(t, env.Validate(AccountRef{Email: "me@example.com", ServerURL: "https://vault.bitwarden.com"}, "boot-1", time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)), ErrAccountMismatch)
}

func TestRecordPINFailureBackoffAndClearsAtMax(t *testing.T) {
	env := UnlockEnvelope{PINMaxFailures: 3}
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	env.RecordPINFailure(now)
	require.Equal(t, 1, env.FailedAttempts)
	require.True(t, env.BackoffUntil.After(now))
	env.RecordPINFailure(now.Add(time.Second))
	env.RecordPINFailure(now.Add(2 * time.Second))
	require.True(t, env.ShouldDeleteAfterFailures())
}
```

Run `rtk go test ./internal/core/session`. Expected: FAIL.

- [ ] **Step 2: Implement types**

Create `internal/core/session/types.go`:

```go
package session

import "time"

type AccountRef struct { Email string `json:"email"`; ServerURL string `json:"serverUrl"` }

type TokenBundle struct { AccountID string `json:"accountId"`; Email string `json:"email"`; ServerURL string `json:"serverUrl"`; AccessToken []byte `json:"accessToken"`; RefreshToken []byte `json:"refreshToken"`; TokenType string `json:"tokenType"`; ExpiresAt time.Time `json:"expiresAt"`; UpdatedAt time.Time `json:"updatedAt"` }
func (t TokenBundle) Clone() TokenBundle { return TokenBundle{AccountID: t.AccountID, Email: t.Email, ServerURL: t.ServerURL, AccessToken: append([]byte(nil), t.AccessToken...), RefreshToken: append([]byte(nil), t.RefreshToken...), TokenType: t.TokenType, ExpiresAt: t.ExpiresAt, UpdatedAt: t.UpdatedAt} }
func (t *TokenBundle) Close() { if t == nil { return }; zero(t.AccessToken); zero(t.RefreshToken); t.AccessToken = nil; t.RefreshToken = nil }

type UnlockMaterial struct { CacheKey []byte `json:"cacheKey"`; UserKey []byte `json:"userKey"` }
func (m UnlockMaterial) Clone() UnlockMaterial { return UnlockMaterial{CacheKey: append([]byte(nil), m.CacheKey...), UserKey: append([]byte(nil), m.UserKey...)} }
func (m *UnlockMaterial) Close() { if m == nil { return }; zero(m.CacheKey); zero(m.UserKey); m.CacheKey = nil; m.UserKey = nil }

type UnlockEnvelope struct { Version int `json:"version"`; Account AccountRef `json:"account"`; AccountID string `json:"accountId"`; BootID string `json:"bootId"`; ExpiresAt time.Time `json:"expiresAt"`; KDF string `json:"kdf"`; KDFTime uint32 `json:"kdfTime"`; KDFMemory uint32 `json:"kdfMemory"`; KDFThreads uint8 `json:"kdfThreads"`; Salt []byte `json:"salt"`; Ciphertext []byte `json:"ciphertext"`; FailedAttempts int `json:"failedAttempts"`; PINMaxFailures int `json:"pinMaxFailures"`; BackoffUntil time.Time `json:"backoffUntil"` }
const UnlockEnvelopeVersion = 1

type AuthStatus string
const ( AuthStatusKeyringUnavailable AuthStatus = "keyring_unavailable"; AuthStatusUnauthenticated AuthStatus = "unauthenticated"; AuthStatusLoggedInLocked AuthStatus = "logged_in_locked"; AuthStatusUnlockAvailable AuthStatus = "logged_in_unlock_available" )
func zero(b []byte) { for i := range b { b[i] = 0 } }
```

Create `internal/core/session/envelope.go`:

```go
package session

import ("errors"; "time")
var ( ErrUnlockExpired = errors.New("session: local unlock expired"); ErrBootChanged = errors.New("session: boot id changed"); ErrAccountMismatch = errors.New("session: account mismatch"); ErrPINBackoff = errors.New("session: pin backoff active") )
func (e UnlockEnvelope) Validate(ref AccountRef, bootID string, now time.Time) error { if e.Account != ref { return ErrAccountMismatch }; if e.BootID != bootID { return ErrBootChanged }; if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) { return ErrUnlockExpired }; if !e.BackoffUntil.IsZero() && now.Before(e.BackoffUntil) { return ErrPINBackoff }; return nil }
func (e *UnlockEnvelope) RecordPINFailure(now time.Time) { e.FailedAttempts++; if e.PINMaxFailures <= 0 { e.PINMaxFailures = 5 }; backoff := time.Duration(1<<min(e.FailedAttempts-1, 5)) * time.Second; if backoff > time.Minute { backoff = time.Minute }; e.BackoffUntil = now.Add(backoff) }
func (e UnlockEnvelope) ShouldDeleteAfterFailures() bool { max := e.PINMaxFailures; if max <= 0 { max = 5 }; return e.FailedAttempts >= max }
```

Run:

```bash
rtk gofmt -w internal/core/session
rtk go test ./internal/core/session
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
rtk git add internal/core/session
rtk git commit -m "feat: add keyring session domain"
```

#### Sub-task 2: Add credential port and keyring adapter with availability check

- [ ] **Step 1: Add dependency and tests**

Run:

```bash
rtk go get github.com/zalando/go-keyring@latest
```

Create `internal/adapters/secrets/keyring/store_test.go`:

```go
func TestStoreTokenBundleLookupIgnoresAccountID(t *testing.T) {
	backend := &fakeBackend{data: map[string]string{}}
	store := NewForBackend(backend)
	ref := session.AccountRef{Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	bundle := session.TokenBundle{AccountID: "acct", Email: ref.Email, ServerURL: ref.ServerURL, AccessToken: []byte("access"), RefreshToken: []byte("refresh")}
	require.NoError(t, store.SaveTokenBundle(context.Background(), ref, bundle))
	loaded, err := store.LoadTokenBundle(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, "acct", loaded.AccountID)
	require.Equal(t, []byte("refresh"), loaded.RefreshToken)
}

func TestCheckAvailableTouchesBackendBeforeLogin(t *testing.T) {
	backend := &fakeBackend{data: map[string]string{}}
	store := NewForBackend(backend)
	require.NoError(t, store.CheckAvailable(context.Background()))
	require.True(t, backend.checked)
}
```

Define `fakeBackend` with `Set/Get/Delete` and `checked` flag in the test.

- [ ] **Step 2: Implement port and adapter**

Create `internal/ports/out/credentials.go`:

```go
package out

import ("context"; session "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session")
type CredentialStore interface { CheckAvailable(ctx context.Context) error; SaveTokenBundle(ctx context.Context, ref session.AccountRef, bundle session.TokenBundle) error; LoadTokenBundle(ctx context.Context, ref session.AccountRef) (session.TokenBundle, error); DeleteTokenBundle(ctx context.Context, ref session.AccountRef) error; SaveUnlockEnvelope(ctx context.Context, ref session.AccountRef, envelope session.UnlockEnvelope) error; LoadUnlockEnvelope(ctx context.Context, ref session.AccountRef) (session.UnlockEnvelope, error); DeleteUnlockEnvelope(ctx context.Context, ref session.AccountRef) error }
type BootIDProvider interface { BootID(ctx context.Context) (string, error) }
type PINEnvelopeService interface { Create(ctx context.Context, ref session.AccountRef, material session.UnlockMaterial, pin string, bootID string) (session.UnlockEnvelope, error); Open(ctx context.Context, ref session.AccountRef, envelope session.UnlockEnvelope, pin string, bootID string) (session.UnlockMaterial, session.UnlockEnvelope, error) }
```

Create `internal/adapters/secrets/keyring/store.go` with lookup keys based only on `normalize(email)+serverURL`:

```go
func refHash(ref session.AccountRef) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(ref.Email)) + "\x00" + strings.TrimRight(ref.ServerURL, "/")))
	return hex.EncodeToString(h[:16])
}
```

`CheckAvailable` must `Set`, `Get`, and `Delete` a probe secret under service `gtk4-layershell-bitwarden/probe` and user `availability`. On any backend error other than deleting an already-missing probe, return a wrapped error containing `Secret Service is required`.

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/ports/out/credentials.go internal/adapters/secrets/keyring
rtk go test ./internal/adapters/secrets/keyring ./internal/core/session
rtk git add go.mod go.sum internal/ports/out/credentials.go internal/adapters/secrets/keyring
rtk git commit -m "feat: add secret service credential store"
```

Expected: PASS.

#### Sub-task 3: Add boot ID and PIN envelope service with failure persistence support

- [ ] **Step 1: Write tests**

Create `internal/adapters/session/pinenvelope/service_test.go`:

```go
func TestCreateOpenEnvelopeWithCorrectPIN(t *testing.T) {
	svc := New(ServiceConfig{TTL: time.Hour, MaxFailures: 5})
	ref := session.AccountRef{Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	material := session.UnlockMaterial{CacheKey: []byte("01234567890123456789012345678901"), UserKey: []byte("user-key")}
	env, err := svc.Create(context.Background(), ref, material, "123456", "boot-1")
	require.NoError(t, err)
	opened, updated, err := svc.Open(context.Background(), ref, env, "123456", "boot-1")
	require.NoError(t, err)
	require.False(t, updated.ShouldDeleteAfterFailures())
	require.Equal(t, material.CacheKey, opened.CacheKey)
	require.Equal(t, material.UserKey, opened.UserKey)
}

func TestOpenEnvelopeWrongPINRecordsFailure(t *testing.T) {
	svc := New(ServiceConfig{TTL: time.Hour, MaxFailures: 2})
	ref := session.AccountRef{Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	env, err := svc.Create(context.Background(), ref, session.UnlockMaterial{CacheKey: []byte("01234567890123456789012345678901")}, "123456", "boot-1")
	require.NoError(t, err)
	_, updated, err := svc.Open(context.Background(), ref, env, "000000", "boot-1")
	require.ErrorIs(t, err, ErrInvalidPIN)
	require.Equal(t, 1, updated.FailedAttempts)
}
```

- [ ] **Step 2: Implement boot ID and PIN envelope**

Create `internal/adapters/session/bootid/bootid_linux.go` to read `/proc/sys/kernel/random/boot_id`. Create non-Linux stub returning `non-linux-test-boot`.

Create `internal/adapters/session/pinenvelope/service.go` where `Open` returns `(session.UnlockMaterial, session.UnlockEnvelope, error)`. On wrong PIN, call `envelope.RecordPINFailure(time.Now())` and return the updated envelope so app service can save it or delete it after max failures.

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/adapters/session
rtk go test ./internal/adapters/session/...
rtk git add internal/adapters/session
rtk git commit -m "feat: add pin unlock envelope service"
```

Expected: PASS.

**Phase review checkpoint:** Ask `go-reviewer` and `senior-engineer` to review key derivation, envelope fields, lookup keys, availability checks, and failure policy.

---

## Phase 3: App login, refresh, status, CLI semantics

**Goal:** `login` performs one auth flow, requires PIN, stores token/envelope in Secret Service, refreshes tokens when needed, and never prints `BW_SESSION`.

**Files:**
- Modify `internal/ports/out/remote.go`
- Modify `internal/ports/in/app.go`
- Modify `internal/adapters/remote/bitwarden/client.go`
- Modify `internal/app/state.go`, `service.go`, `service_test.go`
- Modify `internal/adapters/cli/cobra/root.go`, `auth.go`, `auth_test.go`

#### Sub-task 1: Add remote session and refresh methods

- [ ] **Step 1: Write adapter tests**

Add tests proving `RefreshTokenBundle` calls SDK refresh against the correct region/self-hosted environment, returns a new app `TokenBundle`, and nil SDK client returns an error instead of panic.

- [ ] **Step 2: Implement port**

Add to `internal/ports/out/remote.go`:

```go
ExportSession(ctx context.Context) (session.UnlockMaterial, session.TokenBundle, error)
RestoreSession(ctx context.Context, material session.UnlockMaterial, tokens session.TokenBundle) error
RefreshTokenBundle(ctx context.Context, tokens session.TokenBundle) (session.TokenBundle, error)
```

Implement in `internal/adapters/remote/bitwarden/client.go` by mapping to SDK `ExportSession`, `RestoreSession`, and `RefreshSession`. `RefreshTokenBundle` must construct the SDK client for the token bundle server identity before refreshing: use EU endpoints for `https://vault.bitwarden.eu`, US endpoints for `https://vault.bitwarden.com`, and `sdk.WithServerURL(tokens.ServerURL)` for self-hosted URLs. Then seed an SDK token store with the supplied bundle, call `RefreshSession(ctx, tokens.AccountID)`, and return updated tokens with original email/server metadata preserved.

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/ports/out/remote.go internal/adapters/remote/bitwarden
rtk go test ./internal/adapters/remote/bitwarden
rtk git add internal/ports/out/remote.go internal/adapters/remote/bitwarden
rtk git commit -m "feat: bridge remote session refresh"
```

#### Sub-task 2: Add app auth status and token refresh service paths

- [ ] **Step 1: Write app tests**

Add tests in `internal/app/service_test.go`:

```go
func TestAuthStatusUsesKeyringAndEnvelope(t *testing.T) { /* no token => unauthenticated; token no envelope => logged_in_locked; token + valid envelope => unlock_available */ }
func TestEnsureFreshTokensRefreshesAndSavesNearExpiry(t *testing.T) { /* token expires in under 2 minutes, remote returns new token, credentials saved */ }
func TestEnsureFreshTokensDeletesInvalidRefreshToken(t *testing.T) { /* remote invalid refresh -> DeleteTokenBundle called */ }
func TestEnsureFreshTokensKeepsBundleOnTransientFailure(t *testing.T) { /* network error -> no delete */ }
```

Use fakes for `CredentialStore`, `RemoteVault`, and `BootIDProvider`.

- [ ] **Step 2: Implement app APIs**

Add to `internal/ports/in/app.go`:

```go
Login(ctx context.Context, input app.LoginInput) error
UnlockWithPIN(ctx context.Context, email, pin string) error
AuthStatus(ctx context.Context, email string) (session.AuthStatus, error)
```

If importing `app.LoginInput` into `ports/in` creates a cycle, move `LoginInput` to `internal/core/auth` or define it in `ports/in` using only core types.

In `internal/app/service.go`, implement:

- `checkCredentialsAvailable(ctx)` calls `Credentials.CheckAvailable(ctx)` before login/unlock/status.
- `accountRef(email)` returns normalized email + effective server URL; no AccountID in lookup key.
- `ensureFreshTokens(ctx, ref)` loads token bundle, refreshes if `time.Until(ExpiresAt) < 2*time.Minute`, saves refreshed bundle, deletes bundle only for SDK unauthenticated/invalid-grant errors.
- `AuthStatus(ctx,email)` returns the four status values from the spec.

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/app internal/ports/in/app.go
rtk go test ./internal/app -run 'TestAuthStatus|TestEnsureFreshTokens'
rtk git add internal/app internal/ports/in/app.go
rtk git commit -m "feat: add keyring auth status and refresh"
```

#### Sub-task 3: Implement single-pass login with mandatory PIN

- [ ] **Step 1: Write service and CLI tests**

App test: `TestLoginStoresTokenBundleAndPINEnvelope` asserts:

- `Credentials.CheckAvailable` called before remote login.
- remote login called once.
- token bundle saved under email+server ref.
- unlock envelope saved.
- PIN missing returns validation error before remote login.

CLI test: `TestLoginDoesNotPrintBWSessionAndRequiresPIN` asserts output does not contain `BW_SESSION` and contains `local unlock PIN`.

- [ ] **Step 2: Implement `Service.Login`**

`Service.Login` must perform the whole auth flow once:

1. check Secret Service availability
2. validate non-empty PIN
3. perform remote BeginLogin/CompleteTwoFactor through existing `UnlockWithTwoFactor` internals without a prior separate unlock call
4. export SDK session material
5. copy current cache key into `UnlockMaterial.CacheKey`
6. save token bundle
7. create/save PIN envelope
8. clear temporary material

Refactor existing `unlock` internals if necessary so `Login` does not call a public method that causes duplicated CLI prompts or double sync.

- [ ] **Step 3: Split CLI login and unlock flows**

In `internal/adapters/cli/cobra/auth.go`, replace `runLoginUnlock` with separate `runLogin` and `runUnlock` helpers. `runLogin` prompts region/email/master password/2FA/PIN and calls `svc.Login(...)` exactly once. Delete `newSessionKey`, `os.Setenv("BW_SESSION", ...)`, and export guidance.

- [ ] **Step 4: Run tests and commit**

```bash
rtk gofmt -w internal/app internal/adapters/cli/cobra
rtk go test ./internal/app -run TestLoginStoresTokenBundleAndPINEnvelope
rtk go test ./internal/adapters/cli/cobra -run 'TestLoginDoesNotPrintBWSessionAndRequiresPIN|TestLogin'
rtk git add internal/app internal/adapters/cli/cobra
rtk git commit -m "feat: require pin backed keyring login"
```

#### Sub-task 4: Compose dependencies and fail fast in commands

- [ ] **Step 1: Wire adapters**

In `internal/adapters/cli/cobra/root.go`, compose `keyring.New()`, `bootid.New()`, and `pinenvelope.New(...)`. Pass them to `app.Deps`.

Before CLI login prompts for master password, call service `CheckAuthStorage(ctx)` or use `svc.Login`, which checks availability before remote login. For `status`, call `AuthStatus`; if `CheckAvailable` fails, return `keyring_unavailable` status without attempting token reads.

- [ ] **Step 2: Run full app tests and commit**

```bash
rtk gofmt -w internal/adapters/cli/cobra/root.go
rtk go test ./...
rtk git add internal/adapters/cli/cobra/root.go
rtk git commit -m "feat: compose keyring session services"
```

**Phase review checkpoint:** Ask `go-reviewer` and `senior-engineer` to review login semantics, refresh handling, no `BW_SESSION`, and Secret Service fail-fast behavior.

---

## Phase 4: Overlay PIN prompt and bounded plaintext access

**Goal:** Overlay startup uses `AuthStatus` to choose the correct prompt, PIN unlock restores session, and search no longer depends on an indefinitely resident plaintext index.

**Files:**
- Modify `internal/app/service.go`, `service_test.go`
- Modify `internal/ports/in/app.go`
- Modify `internal/adapters/gui/omnibox/omnibox.go`, `view_linux.go`, tests

#### Sub-task 1: Add PIN unlock with failure persistence

- [ ] **Step 1: Write tests**

Add tests:

- valid PIN: loads tokens/envelope by email+server, opens envelope, restores remote session, installs only transient keys.
- wrong PIN: saves updated envelope with incremented failed attempts.
- max failures: deletes unlock envelope and returns master-password-required error.
- expired/reboot-changed envelope: returns master-password-required error and does not restore remote session.

- [ ] **Step 2: Implement `UnlockWithPIN`**

`UnlockWithPIN(ctx,email,pin)`:

1. check keyring availability
2. load and refresh token bundle
3. load envelope
4. get boot id
5. open envelope via `PINEnvelopeService.Open`, receiving both unlock material and the updated envelope
6. on wrong PIN, save the updated envelope or delete after max failures
7. on success, restore remote session and install only cache key/user key needed for immediate operations
8. clear copied material

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/app
rtk go test ./internal/app -run 'TestUnlockWithPIN|TestPINFailure'
rtk git add internal/app
rtk git commit -m "feat: unlock local session with pin"
```

#### Sub-task 2: Add overlay auth-status driven PIN mode

- [ ] **Step 1: Add state tests**

Add tests that `AuthStatusUnlockAvailable` starts in PIN mode, `AuthStatusLoggedInLocked` starts in master-password mode, `AuthStatusUnauthenticated` starts onboarding/login, and `AuthStatusKeyringUnavailable` shows an error.

- [ ] **Step 2: Implement UI mode**

Add `ModePINUnlock` to omnibox state. On startup, call `service.AuthStatus(ctx,email)` and choose mode. Add compact PIN password entry similar to sekeve. On submit, call `service.UnlockWithPIN(ctx,email,pin)`.

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/adapters/gui/omnibox
rtk go test ./internal/adapters/gui/omnibox
rtk go test -tags nogtk ./...
rtk git add internal/adapters/gui/omnibox
rtk git commit -m "feat: add overlay pin unlock mode"
```

#### Sub-task 3: Bound plaintext search state with current signatures

- [ ] **Step 1: Write tests**

Add `TestSearchDoesNotLeavePlaintextItemsResidentAfterOperation` using current signature:

```go
results, err := svc.Search(context.Background(), "git", 10)
require.NoError(t, err)
require.Len(t, results, 1)
require.Nil(t, svc.items)
require.Nil(t, svc.index)
```

Add similar tests for `Get(ctx,id)` if item detail currently reads from resident `s.items`.

- [ ] **Step 2: Refactor search/detail access**

Add helper `loadCachedVaultWithKey(ctx,key)` that reads encrypted cache, opens with `SecretBox`, decodes items/folders/outbox, and returns local slices without installing them on `Service`. Update `Search(ctx, query, limit)` to build an index locally and return `[]vault.ScoredItem`. Update `Get(ctx,id)` to scan locally loaded items when no resident items exist.

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/app
rtk go test ./internal/app -run 'TestSearchDoesNotLeavePlaintext|TestGet'
rtk git add internal/app
rtk git commit -m "refactor: bound plaintext vault reads"
```

**Phase review checkpoint:** Ask `go-reviewer` and `senior-engineer` to review overlay state selection, PIN failure persistence, and plaintext lifetime.

---

## Phase 5: Command semantics, docs, validation, install

**Goal:** Runtime semantics match the approved spec and the installed binary is ready for local testing.

**Files:**
- Modify `internal/adapters/cli/cobra/root.go`, `root_test.go`, `auth.go`, `auth_test.go`
- Modify `README.md`

#### Sub-task 1: Update lock/logout/status semantics

- [ ] **Step 1: Write tests**

Tests:

- `lock` deletes unlock envelope but keeps token bundle.
- `logout` deletes token bundle, unlock envelope, encrypted cache, encrypted outbox.
- `status` reports `keyring_unavailable`, `unauthenticated`, `logged_in_locked`, or `logged_in_unlock_available` without printing secrets.

- [ ] **Step 2: Implement commands**

`lock` calls `CredentialStore.DeleteUnlockEnvelope(ctx, ref)` and prints `Local unlock cleared.`

`logout` calls `DeleteUnlockEnvelope`, `DeleteTokenBundle`, then clears cache/outbox.

`status` calls `AppService.AuthStatus(ctx,email)` and prints JSON with `status`, `userEmail`, `serverUrl`, and `lastSync` only.

- [ ] **Step 3: Run tests and commit**

```bash
rtk gofmt -w internal/adapters/cli/cobra
rtk go test ./internal/adapters/cli/cobra -run 'TestLock|TestLogout|TestStatus'
rtk git add internal/adapters/cli/cobra
rtk git commit -m "fix: align cli session semantics"
```

#### Sub-task 2: Update docs and remove runtime `BW_SESSION` references

- [ ] **Step 1: Update README**

Replace the existing `BW_SESSION` section with:

```md
`login` stores Bitwarden server tokens in Linux Secret Service and requires a local unlock PIN. The PIN unwraps a short-lived local unlock envelope and is never sent to Bitwarden.

`lock` clears the local PIN unlock envelope but keeps Bitwarden tokens. `logout` removes Bitwarden tokens, the local unlock envelope, encrypted cache, and encrypted outbox.

The app does not use `BW_SESSION`. Access tokens, refresh tokens, PINs, and vault keys are never printed.
```

- [ ] **Step 2: Verify no runtime references remain and commit**

```bash
rtk grep -n "BW_SESSION" README.md internal || true
rtk git add README.md
rtk git commit -m "docs: document keyring pin sessions"
```

Expected: only specs/tests may mention `BW_SESSION` as removed behavior.

#### Sub-task 3: Full validation, final review, install

- [ ] **Step 1: SDK validation**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk go test ./...
rtk go test -race ./...
rtk golangci-lint run ./...
rtk make check
```

- [ ] **Step 2: App validation**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk go test ./...
rtk go test -race ./...
rtk golangci-lint run ./...
rtk make safety
rtk go test -tags nogtk ./...
```

- [ ] **Step 3: Final reviews**

Ask `go-reviewer` for full diff review. Ask `senior-engineer` for final architecture/spec compliance review. Run CodeRabbit only if requested.

- [ ] **Step 4: Install**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk make install
```

Expected: install succeeds and binary no longer prints `BW_SESSION`.

**Phase review checkpoint:** Confirm spec coverage, no runtime `BW_SESSION`, keyring fail-fast, token refresh save-back/delete behavior, PIN backoff/delete behavior, and no plaintext secrets in cache/outbox.

---

## Plan self-review

- Secret Service mandatory and fail-fast: Phase 2 `CheckAvailable`, Phase 3 command/service checks.
- Keyring lookup before account ID is known: Phase 2 uses normalized email + server URL only.
- No daemon: no daemon/socket/systemd work appears.
- Mandatory PIN after login: Phase 3 single-pass login.
- Token refresh: Phase 1 SDK public refresh, Phase 3 app save-back/delete/preserve semantics.
- PIN envelope wraps cache key and Bitwarden user key: spec and phases explicitly state this and its risk.
- PIN failure persistence: Phase 2 domain/envelope, Phase 4 app save/delete behavior.
- Overlay startup decision: Phase 3 `AuthStatus`, Phase 4 UI mode selection.
- Bounded plaintext: Phase 4 uses current `Search(ctx, query, limit)` and `vault.ScoredItem` signatures.
- No placeholders remain in implementation steps.
