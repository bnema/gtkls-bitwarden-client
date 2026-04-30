# Keyring PIN Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan phase-by-phase. Each phase contains sub-tasks with checkbox steps (`- [ ]`) for tracking. Review gates happen at the end of each phase, not after every sub-task.

**Goal:** Replace placeholder `BW_SESSION` auth with Linux Secret Service token storage, mandatory local PIN unlock envelopes, and bounded vault plaintext lifetime.

**Architecture:** Extend `bitwarden-go-sdk` with public session export/restore and token-store injection so the app can persist Bitwarden server tokens and wrapped vault material outside SDK internals. In `gtk4-layershell-bitwarden`, keep auth/session policy in core/app ports, implement Secret Service and PIN-envelope mechanics as adapters, and refactor CLI/overlay flows to use token bundles plus local unlock envelopes instead of process-local `BW_SESSION` strings.

**Tech Stack:** Go 1.26, Cobra/Viper, `github.com/zalando/go-keyring`, XChaCha20-Poly1305, Argon2id, existing `bitwarden-go-sdk` local replace, GTK4 layer-shell.

---

## Scope check

This work spans two repositories because the app cannot persist or restore SDK authentication state through the current public SDK API. The feature is still one coherent auth/session change: the SDK phase provides the smallest public surface needed by the app, and the remaining phases implement the approved app spec.

Repositories:

- SDK: `/home/brice/dev/projects/bitwarden-go-sdk`
- App: `/home/brice/dev/projects/gtk4-layershell-bitwarden`

Use normal branches, not a new worktree, unless the user changes that choice before implementation.

---

## File structure

### SDK files

- Modify `bitwarden/types.go`: add public `TokenSet`, `SessionMaterial`, `TokenStore`, and token helpers.
- Modify `bitwarden/options.go`: add exported `WithTokenStore` option.
- Modify `bitwarden/auth.go`: return session material on login and add `ExportSession`/`RestoreSession` helpers.
- Modify `bitwarden/client.go`: wire public token-store adapter into internal ports and restore unlocked user key state.
- Add `bitwarden/token_store.go`: adapter between public token-store interface and internal `ports.TokenStore`.
- Add or modify tests in `bitwarden/auth_test.go`, `bitwarden/session_test.go`, and `bitwarden/client_test.go`.

### App core/ports files

- Add `internal/core/session/types.go`: account refs, token bundles, unlock envelopes, PIN policy, status values.
- Add `internal/core/session/envelope.go`: pure validation helpers for expiry, boot id, and account matching.
- Add `internal/ports/out/credentials.go`: `CredentialStore`, `BootIDProvider`, and `PINEnvelopeService` ports.
- Modify `internal/ports/out/remote.go`: add session export/restore methods needed by app service.
- Modify `internal/app/state.go`: replace long-lived unlocked assumptions with explicit transient unlock material fields.
- Modify `internal/app/service.go`: implement login token persistence, mandatory PIN setup, PIN unlock, lock/logout semantics, and bounded memory cleanup.

### App adapter files

- Add `internal/adapters/secrets/keyring/store.go`: Secret Service credential store using `zalando/go-keyring`.
- Add `internal/adapters/secrets/keyring/store_test.go`: tests through a small backend seam.
- Add `internal/adapters/session/bootid/bootid_linux.go`: read `/proc/sys/kernel/random/boot_id`.
- Add `internal/adapters/session/bootid/bootid_stub.go`: non-Linux test fallback.
- Add `internal/adapters/session/pinenvelope/service.go`: Argon2id + XChaCha20-Poly1305 PIN envelope implementation.
- Add `internal/adapters/session/pinenvelope/service_test.go`.
- Modify `internal/adapters/remote/bitwarden/client.go`: bridge SDK session export/restore and keyring token store.
- Modify `internal/adapters/cli/cobra/auth.go`: remove `BW_SESSION`, add mandatory PIN prompts and updated messages.
- Modify `internal/adapters/cli/cobra/auth_test.go`: assert no `BW_SESSION`, assert PIN onboarding.
- Modify `internal/adapters/cli/cobra/root.go`: compose keyring store, boot id provider, and PIN envelope service.
- Modify `internal/adapters/gui/omnibox/view_linux.go`: add compact PIN prompt path before master-password prompt when a valid envelope exists.
- Modify `README.md`: update login/unlock/lock/logout/status documentation.

---

## Phase 1: SDK public session and token-store surface

**Goal:** The SDK can persist tokens through a public token-store interface and export/restore unlocked session material without app imports of internal SDK packages.

**Files:**
- Create: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/token_store.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/types.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/options.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/auth.go`
- Modify: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/client.go`
- Test: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/auth_test.go`
- Test: `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/session_test.go`

#### Sub-task 1: Add public token/session types

- [ ] **Step 1: Write the failing type usage test**

Add to `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/session_test.go`:

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
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk go test ./bitwarden -run TestSessionMaterialCloneDoesNotShareSecretSlices
```

Expected: FAIL because `SessionMaterial`, `TokenSet`, or `Clone` is undefined.

- [ ] **Step 3: Add public types**

Add to `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/types.go`:

```go
type TokenSet struct {
	AccountID    string
	AccessToken  []byte
	RefreshToken []byte
	TokenType    string
	ExpiresAt    time.Time
}

func (t TokenSet) Clone() TokenSet {
	return TokenSet{
		AccountID:    t.AccountID,
		AccessToken:  append([]byte(nil), t.AccessToken...),
		RefreshToken: append([]byte(nil), t.RefreshToken...),
		TokenType:    t.TokenType,
		ExpiresAt:    t.ExpiresAt,
	}
}

func (t *TokenSet) Close() {
	if t == nil {
		return
	}
	for i := range t.AccessToken {
		t.AccessToken[i] = 0
	}
	for i := range t.RefreshToken {
		t.RefreshToken[i] = 0
	}
	t.AccessToken = nil
	t.RefreshToken = nil
}

type SessionMaterial struct {
	AccountID string
	UserKey   []byte
	Tokens    TokenSet
}

func (s SessionMaterial) Clone() SessionMaterial {
	return SessionMaterial{
		AccountID: s.AccountID,
		UserKey:   append([]byte(nil), s.UserKey...),
		Tokens:    s.Tokens.Clone(),
	}
}

func (s *SessionMaterial) Close() {
	if s == nil {
		return
	}
	for i := range s.UserKey {
		s.UserKey[i] = 0
	}
	s.UserKey = nil
	s.Tokens.Close()
}
```

Add `time` to the import block in `types.go` if that file does not already import it.

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk gofmt -w bitwarden/types.go bitwarden/session_test.go
rtk go test ./bitwarden -run TestSessionMaterialCloneDoesNotShareSecretSlices
```

Expected: PASS.

- [ ] **Step 5: Commit the sub-task work**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk git add bitwarden/types.go bitwarden/session_test.go
rtk git commit -m "feat: add public session material types"
```

#### Sub-task 2: Add public token-store injection

- [ ] **Step 1: Write the failing token-store test**

Add to `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/client_test.go`:

```go
type publicTokenStoreStub struct {
	saved   TokenSet
	loaded  TokenSet
	deleted string
}

func (s *publicTokenStoreStub) SaveTokens(_ context.Context, tokens TokenSet) error {
	s.saved = tokens.Clone()
	s.loaded = tokens.Clone()
	return nil
}

func (s *publicTokenStoreStub) LoadTokens(_ context.Context, accountID string) (TokenSet, error) {
	if s.loaded.AccountID != accountID {
		return TokenSet{}, ErrNotFound
	}
	return s.loaded.Clone(), nil
}

func (s *publicTokenStoreStub) DeleteTokens(_ context.Context, accountID string) error {
	s.deleted = accountID
	return nil
}

func TestWithTokenStoreSavesLoginTokens(t *testing.T) {
	identity, crypto, _ := publicAuthDeps(t)
	store := &publicTokenStoreStub{}
	masterKey := ports.MasterKey{Bytes: []byte("master")}
	userKey := ports.UserKey{Bytes: []byte("user")}
	tokens := ports.TokenSet{
		AccountID:    "account-1",
		AccessToken:  ports.NewSecretBytes([]byte("access")),
		RefreshToken: ports.NewSecretBytes([]byte("refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

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

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk go test ./bitwarden -run TestWithTokenStoreSavesLoginTokens
```

Expected: FAIL because `TokenStore`, `WithTokenStore`, and `ErrNotFound` are undefined.

- [ ] **Step 3: Implement token-store adapter**

Create `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/token_store.go`:

```go
package bitwarden

import (
	"context"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

var ErrNotFound = &Error{Kind: ErrorKindNotFound, Op: "TokenStore", Message: "tokens not found"}

type TokenStore interface {
	SaveTokens(ctx context.Context, tokens TokenSet) error
	LoadTokens(ctx context.Context, accountID string) (TokenSet, error)
	DeleteTokens(ctx context.Context, accountID string) error
}

type publicTokenStoreAdapter struct {
	store TokenStore
}

func (a publicTokenStoreAdapter) SaveTokens(ctx context.Context, tokens ports.TokenSet) error {
	access := tokens.AccessToken.Bytes()
	refresh := tokens.RefreshToken.Bytes()
	return a.store.SaveTokens(ctx, TokenSet{
		AccountID:    tokens.AccountID,
		AccessToken:  append([]byte(nil), access...),
		RefreshToken: append([]byte(nil), refresh...),
		TokenType:    tokens.TokenType,
		ExpiresAt:    tokens.ExpiresAt,
	})
}

func (a publicTokenStoreAdapter) LoadTokens(ctx context.Context, accountID string) (ports.TokenSet, error) {
	tokens, err := a.store.LoadTokens(ctx, accountID)
	if err != nil {
		return ports.TokenSet{}, err
	}
	return internalTokenSet(tokens), nil
}

func (a publicTokenStoreAdapter) DeleteTokens(ctx context.Context, accountID string) error {
	return a.store.DeleteTokens(ctx, accountID)
}

func internalTokenSet(tokens TokenSet) ports.TokenSet {
	return ports.TokenSet{
		AccountID:    tokens.AccountID,
		AccessToken:  ports.NewSecretBytes(tokens.AccessToken),
		RefreshToken: ports.NewSecretBytes(tokens.RefreshToken),
		TokenType:    tokens.TokenType,
		ExpiresAt:    tokens.ExpiresAt,
	}
}

func publicTokenSet(tokens ports.TokenSet) TokenSet {
	return TokenSet{
		AccountID:    tokens.AccountID,
		AccessToken:  append([]byte(nil), tokens.AccessToken.Bytes()...),
		RefreshToken: append([]byte(nil), tokens.RefreshToken.Bytes()...),
		TokenType:    tokens.TokenType,
		ExpiresAt:    tokens.ExpiresAt,
	}
}

func tokenStoreError(err error) error {
	if err == nil {
		return nil
	}
	if core, ok := err.(*coreerrors.Error); ok && core.Kind == coreerrors.KindNotFound {
		return ErrNotFound
	}
	return err
}
```

Modify `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/options.go`:

```go
func WithTokenStore(tokens TokenStore) Option {
	return func(cfg *clientConfig) error {
		if tokens != nil {
			cfg.tokens = publicTokenStoreAdapter{store: tokens}
		}
		return nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk gofmt -w bitwarden
rtk go test ./bitwarden -run TestWithTokenStoreSavesLoginTokens
```

Expected: PASS.

- [ ] **Step 5: Commit the sub-task work**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk git add bitwarden/token_store.go bitwarden/options.go bitwarden/client_test.go
rtk git commit -m "feat: expose token store injection"
```

#### Sub-task 3: Add session export and restore

- [ ] **Step 1: Write failing session export/restore tests**

Add to `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/session_test.go`:

```go
func TestExportSessionReturnsUnlockedMaterial(t *testing.T) {
	identity, crypto, store := publicAuthDeps(t)
	masterKey := ports.MasterKey{Bytes: []byte("master")}
	userKey := ports.UserKey{Bytes: []byte("user-key")}
	tokens := ports.TokenSet{AccountID: "account-1", AccessToken: ports.NewSecretBytes([]byte("access")), RefreshToken: ports.NewSecretBytes([]byte("refresh")), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-1", EncryptedUserKey: "enc-user"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user"}).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)
	store.EXPECT().LoadTokens(mock.Anything, "account-1").Return(tokens, nil)

	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)
	require.NoError(t, client.Login(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"}))

	material, err := client.ExportSession(context.Background())
	require.NoError(t, err)
	require.Equal(t, "account-1", material.AccountID)
	require.Equal(t, []byte("user-key"), material.UserKey)
	require.Equal(t, []byte("access"), material.Tokens.AccessToken)
}

func TestRestoreSessionUnlocksClient(t *testing.T) {
	client, err := NewClient()
	require.NoError(t, err)

	material := SessionMaterial{
		AccountID: "account-1",
		UserKey:   []byte("user-key"),
		Tokens:    TokenSet{AccountID: "account-1", AccessToken: []byte("access"), RefreshToken: []byte("refresh"), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)},
	}
	require.NoError(t, client.RestoreSession(context.Background(), material))
	require.False(t, client.IsLocked())

	exported, err := client.ExportSession(context.Background())
	require.NoError(t, err)
	require.Equal(t, "account-1", exported.AccountID)
	require.Equal(t, []byte("user-key"), exported.UserKey)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk go test ./bitwarden -run 'TestExportSessionReturnsUnlockedMaterial|TestRestoreSessionUnlocksClient'
```

Expected: FAIL because `ExportSession` and `RestoreSession` are undefined.

- [ ] **Step 3: Implement export and restore**

Add to `/home/brice/dev/projects/bitwarden-go-sdk/bitwarden/auth.go`:

```go
func (c *Client) ExportSession(ctx context.Context) (SessionMaterial, error) {
	c.mu.Lock()
	accountID := c.accountID
	userKey := c.userKey.Clone()
	c.mu.Unlock()
	if accountID == "" || c.IsLocked() {
		userKey.Close()
		return SessionMaterial{}, &Error{Kind: ErrorKindLocked, Op: "Client.ExportSession", Message: "client is locked"}
	}
	tokens, err := c.tokens.LoadTokens(ctx, accountID)
	if err != nil {
		userKey.Close()
		return SessionMaterial{}, mapCoreError(err)
	}
	return SessionMaterial{AccountID: accountID, UserKey: append([]byte(nil), userKey.Bytes()...), Tokens: publicTokenSet(tokens)}, nil
}

func (c *Client) RestoreSession(ctx context.Context, material SessionMaterial) error {
	if material.AccountID == "" || len(material.UserKey) == 0 {
		return &Error{Kind: ErrorKindValidation, Op: "Client.RestoreSession", Message: "account id and user key are required"}
	}
	cloned := material.Clone()
	if cloned.Tokens.AccountID == "" {
		cloned.Tokens.AccountID = cloned.AccountID
	}
	if len(cloned.Tokens.AccessToken) > 0 || len(cloned.Tokens.RefreshToken) > 0 {
		if err := c.tokens.SaveTokens(ctx, internalTokenSet(cloned.Tokens)); err != nil {
			cloned.Close()
			return mapCoreError(err)
		}
	}
	c.mu.Lock()
	c.userKey.Close()
	c.accountID = cloned.AccountID
	c.userKey = ports.UserKey{Bytes: append([]byte(nil), cloned.UserKey...)}
	installed := c.userKey.Clone()
	c.mu.Unlock()
	c.locked.Store(false)
	c.vaultService.SetUserKey(installed)
	c.vaultService.SetLocked(false)
	cloned.Close()
	return nil
}
```

If `ports.UserKey` lacks `Clone` or `Bytes`, inspect `/home/brice/dev/projects/bitwarden-go-sdk/internal/ports/crypto.go` and use the existing methods available there.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk gofmt -w bitwarden
rtk go test ./bitwarden -run 'TestExportSessionReturnsUnlockedMaterial|TestRestoreSessionUnlocksClient'
```

Expected: PASS.

- [ ] **Step 5: Run SDK validation and commit**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk go test ./...
rtk go test -race ./...
rtk golangci-lint run ./...
rtk git add bitwarden
rtk git commit -m "feat: export and restore sdk sessions"
```

Expected: tests pass, race tests pass, lint reports no issues.

**Phase review checkpoint:**
- Ask `go-reviewer` to review SDK public API, token secret handling, and tests.
- Ask `senior-engineer` to review whether the SDK additions are minimal and stable.

---

## Phase 2: App session model, Secret Service store, and PIN envelopes

**Goal:** The app has testable core types and adapters for keyring-backed credentials and PIN-wrapped local unlock material.

**Files:**
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/core/session/types.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/core/session/envelope.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/core/session/envelope_test.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/ports/out/credentials.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/secrets/keyring/store.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/secrets/keyring/store_test.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/bootid/bootid_linux.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/bootid/bootid_stub.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/pinenvelope/service.go`
- Create: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/pinenvelope/service_test.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/go.mod`

#### Sub-task 1: Add session domain types and validation

- [ ] **Step 1: Write failing validation tests**

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/core/session/envelope_test.go`:

```go
package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUnlockEnvelopeUsableWhenAccountBootAndExpiryMatch(t *testing.T) {
	ref := AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	env := UnlockEnvelope{Account: ref, BootID: "boot-1", ExpiresAt: time.Date(2026, 4, 28, 12, 30, 0, 0, time.UTC)}
	err := env.Validate(ref, "boot-1", time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
}

func TestUnlockEnvelopeRejectsExpiredBootAndAccountMismatch(t *testing.T) {
	ref := AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	env := UnlockEnvelope{Account: ref, BootID: "boot-1", ExpiresAt: time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)}
	require.ErrorIs(t, env.Validate(ref, "boot-1", time.Date(2026, 4, 28, 12, 1, 0, 0, time.UTC)), ErrUnlockExpired)
	require.ErrorIs(t, env.Validate(ref, "boot-2", time.Date(2026, 4, 28, 11, 0, 0, 0, time.UTC)), ErrBootChanged)
	require.ErrorIs(t, env.Validate(AccountRef{AccountID: "other", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}, "boot-1", time.Date(2026, 4, 28, 11, 0, 0, 0, time.UTC)), ErrAccountMismatch)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk go test ./internal/core/session
```

Expected: FAIL because package/types are missing.

- [ ] **Step 3: Implement session types**

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/core/session/types.go`:

```go
package session

import "time"

type AccountRef struct {
	AccountID string `json:"accountId"`
	Email     string `json:"email"`
	ServerURL string `json:"serverUrl"`
}

type TokenBundle struct {
	AccountID    string    `json:"accountId"`
	Email        string    `json:"email"`
	ServerURL    string    `json:"serverUrl"`
	AccessToken  []byte    `json:"accessToken"`
	RefreshToken []byte    `json:"refreshToken"`
	TokenType    string    `json:"tokenType"`
	ExpiresAt    time.Time `json:"expiresAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func (t TokenBundle) Clone() TokenBundle {
	return TokenBundle{
		AccountID:    t.AccountID,
		Email:        t.Email,
		ServerURL:    t.ServerURL,
		AccessToken:  append([]byte(nil), t.AccessToken...),
		RefreshToken: append([]byte(nil), t.RefreshToken...),
		TokenType:    t.TokenType,
		ExpiresAt:    t.ExpiresAt,
		UpdatedAt:    t.UpdatedAt,
	}
}

func (t *TokenBundle) Close() {
	if t == nil {
		return
	}
	for i := range t.AccessToken {
		t.AccessToken[i] = 0
	}
	for i := range t.RefreshToken {
		t.RefreshToken[i] = 0
	}
	t.AccessToken = nil
	t.RefreshToken = nil
}

type UnlockMaterial struct {
	CacheKey []byte `json:"cacheKey"`
	UserKey  []byte `json:"userKey"`
}

func (m UnlockMaterial) Clone() UnlockMaterial {
	return UnlockMaterial{CacheKey: append([]byte(nil), m.CacheKey...), UserKey: append([]byte(nil), m.UserKey...)}
}

func (m *UnlockMaterial) Close() {
	if m == nil {
		return
	}
	for i := range m.CacheKey {
		m.CacheKey[i] = 0
	}
	for i := range m.UserKey {
		m.UserKey[i] = 0
	}
	m.CacheKey = nil
	m.UserKey = nil
}

type UnlockEnvelope struct {
	Version              int       `json:"version"`
	Account              AccountRef `json:"account"`
	BootID               string    `json:"bootId"`
	ExpiresAt            time.Time `json:"expiresAt"`
	KDF                  string    `json:"kdf"`
	KDFTime              uint32    `json:"kdfTime"`
	KDFMemory            uint32    `json:"kdfMemory"`
	KDFThreads           uint8     `json:"kdfThreads"`
	Salt                 []byte    `json:"salt"`
	Ciphertext           []byte    `json:"ciphertext"`
	FailedAttempts       int       `json:"failedAttempts"`
	BackoffUntil         time.Time `json:"backoffUntil"`
}

const UnlockEnvelopeVersion = 1
```

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/core/session/envelope.go`:

```go
package session

import (
	"errors"
	"time"
)

var (
	ErrUnlockExpired  = errors.New("session: local unlock expired")
	ErrBootChanged    = errors.New("session: boot id changed")
	ErrAccountMismatch = errors.New("session: account mismatch")
	ErrPINBackoff     = errors.New("session: pin backoff active")
)

func (e UnlockEnvelope) Validate(ref AccountRef, bootID string, now time.Time) error {
	if e.Account != ref {
		return ErrAccountMismatch
	}
	if e.BootID != bootID {
		return ErrBootChanged
	}
	if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
		return ErrUnlockExpired
	}
	if !e.BackoffUntil.IsZero() && now.Before(e.BackoffUntil) {
		return ErrPINBackoff
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/core/session
rtk go test ./internal/core/session
```

Expected: PASS.

- [ ] **Step 5: Commit the sub-task work**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk git add internal/core/session
rtk git commit -m "feat: add local session domain types"
```

#### Sub-task 2: Add ports and keyring adapter

- [ ] **Step 1: Add dependency**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk go get github.com/zalando/go-keyring@latest
```

Expected: `go.mod` and `go.sum` update.

- [ ] **Step 2: Write keyring adapter tests with fake backend**

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/secrets/keyring/store_test.go`:

```go
package keyring

import (
	"context"
	"testing"
	"time"

	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	"github.com/stretchr/testify/require"
)

type fakeBackend struct{ data map[string]string }

func (f *fakeBackend) Set(service, user, secret string) error {
	if f.data == nil { f.data = map[string]string{} }
	f.data[service+"\x00"+user] = secret
	return nil
}
func (f *fakeBackend) Get(service, user string) (string, error) {
	v, ok := f.data[service+"\x00"+user]
	if !ok { return "", ErrNotFound }
	return v, nil
}
func (f *fakeBackend) Delete(service, user string) error {
	delete(f.data, service+"\x00"+user)
	return nil
}

func TestStoreTokenBundleRoundTrip(t *testing.T) {
	store := NewForBackend(&fakeBackend{})
	ref := coresession.AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	bundle := coresession.TokenBundle{AccountID: "acct", Email: ref.Email, ServerURL: ref.ServerURL, AccessToken: []byte("access"), RefreshToken: []byte("refresh"), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}

	require.NoError(t, store.SaveTokenBundle(context.Background(), ref, bundle))
	loaded, err := store.LoadTokenBundle(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, bundle.AccountID, loaded.AccountID)
	require.Equal(t, []byte("access"), loaded.AccessToken)
	require.Equal(t, []byte("refresh"), loaded.RefreshToken)
}

func TestStoreUnlockEnvelopeDelete(t *testing.T) {
	store := NewForBackend(&fakeBackend{})
	ref := coresession.AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	env := coresession.UnlockEnvelope{Version: coresession.UnlockEnvelopeVersion, Account: ref, BootID: "boot", ExpiresAt: time.Now().Add(time.Minute), Ciphertext: []byte("sealed")}
	require.NoError(t, store.SaveUnlockEnvelope(context.Background(), ref, env))
	require.NoError(t, store.DeleteUnlockEnvelope(context.Background(), ref))
	_, err := store.LoadUnlockEnvelope(context.Background(), ref)
	require.ErrorIs(t, err, ErrNotFound)
}
```

- [ ] **Step 3: Implement port and adapter**

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/ports/out/credentials.go`:

```go
package out

import (
	"context"

	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
)

type CredentialStore interface {
	SaveTokenBundle(ctx context.Context, ref coresession.AccountRef, bundle coresession.TokenBundle) error
	LoadTokenBundle(ctx context.Context, ref coresession.AccountRef) (coresession.TokenBundle, error)
	DeleteTokenBundle(ctx context.Context, ref coresession.AccountRef) error
	SaveUnlockEnvelope(ctx context.Context, ref coresession.AccountRef, envelope coresession.UnlockEnvelope) error
	LoadUnlockEnvelope(ctx context.Context, ref coresession.AccountRef) (coresession.UnlockEnvelope, error)
	DeleteUnlockEnvelope(ctx context.Context, ref coresession.AccountRef) error
}

type BootIDProvider interface {
	BootID(ctx context.Context) (string, error)
}

type PINEnvelopeService interface {
	Create(ctx context.Context, ref coresession.AccountRef, material coresession.UnlockMaterial, pin string, bootID string) (coresession.UnlockEnvelope, error)
	Open(ctx context.Context, ref coresession.AccountRef, envelope coresession.UnlockEnvelope, pin string, bootID string) (coresession.UnlockMaterial, error)
}
```

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/secrets/keyring/store.go`:

```go
package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	zalando "github.com/zalando/go-keyring"
	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
)

var ErrNotFound = errors.New("keyring: secret not found")

type backend interface {
	Set(service, user, secret string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type zalandoBackend struct{}

func (zalandoBackend) Set(service, user, secret string) error { return zalando.Set(service, user, secret) }
func (zalandoBackend) Get(service, user string) (string, error) { return zalando.Get(service, user) }
func (zalandoBackend) Delete(service, user string) error { return zalando.Delete(service, user) }

type Store struct{ backend backend }

func New() *Store { return &Store{backend: zalandoBackend{}} }
func NewForBackend(b backend) *Store { return &Store{backend: b} }

func (s *Store) SaveTokenBundle(ctx context.Context, ref coresession.AccountRef, bundle coresession.TokenBundle) error {
	if err := ctx.Err(); err != nil { return err }
	return s.save(tokenService(ref), keyUser(ref), bundle)
}
func (s *Store) LoadTokenBundle(ctx context.Context, ref coresession.AccountRef) (coresession.TokenBundle, error) {
	if err := ctx.Err(); err != nil { return coresession.TokenBundle{}, err }
	var bundle coresession.TokenBundle
	if err := s.load(tokenService(ref), keyUser(ref), &bundle); err != nil { return coresession.TokenBundle{}, err }
	return bundle, nil
}
func (s *Store) DeleteTokenBundle(ctx context.Context, ref coresession.AccountRef) error {
	if err := ctx.Err(); err != nil { return err }
	return s.delete(tokenService(ref), keyUser(ref))
}
func (s *Store) SaveUnlockEnvelope(ctx context.Context, ref coresession.AccountRef, envelope coresession.UnlockEnvelope) error {
	if err := ctx.Err(); err != nil { return err }
	return s.save(unlockService(ref), keyUser(ref), envelope)
}
func (s *Store) LoadUnlockEnvelope(ctx context.Context, ref coresession.AccountRef) (coresession.UnlockEnvelope, error) {
	if err := ctx.Err(); err != nil { return coresession.UnlockEnvelope{}, err }
	var envelope coresession.UnlockEnvelope
	if err := s.load(unlockService(ref), keyUser(ref), &envelope); err != nil { return coresession.UnlockEnvelope{}, err }
	return envelope, nil
}
func (s *Store) DeleteUnlockEnvelope(ctx context.Context, ref coresession.AccountRef) error {
	if err := ctx.Err(); err != nil { return err }
	return s.delete(unlockService(ref), keyUser(ref))
}

func (s *Store) save(service, user string, value any) error {
	data, err := json.Marshal(value)
	if err != nil { return fmt.Errorf("keyring marshal: %w", err) }
	if err := s.backend.Set(service, user, string(data)); err != nil { return fmt.Errorf("keyring set: %w", err) }
	return nil
}
func (s *Store) load(service, user string, out any) error {
	data, err := s.backend.Get(service, user)
	if err != nil {
		if errors.Is(err, zalando.ErrNotFound) || errors.Is(err, ErrNotFound) { return ErrNotFound }
		return fmt.Errorf("keyring get: %w", err)
	}
	if err := json.Unmarshal([]byte(data), out); err != nil { return fmt.Errorf("keyring decode: %w", err) }
	return nil
}
func (s *Store) delete(service, user string) error {
	if err := s.backend.Delete(service, user); err != nil {
		if errors.Is(err, zalando.ErrNotFound) || errors.Is(err, ErrNotFound) { return nil }
		return fmt.Errorf("keyring delete: %w", err)
	}
	return nil
}
func tokenService(ref coresession.AccountRef) string { return "gtk4-layershell-bitwarden/token/" + refHash(ref) }
func unlockService(ref coresession.AccountRef) string { return "gtk4-layershell-bitwarden/unlock/" + refHash(ref) }
func keyUser(ref coresession.AccountRef) string { if ref.AccountID != "" { return ref.AccountID }; return ref.Email }
func refHash(ref coresession.AccountRef) string {
	h := sha256.Sum256([]byte(ref.Email + "\x00" + ref.AccountID + "\x00" + ref.ServerURL))
	return hex.EncodeToString(h[:16])
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/ports/out/credentials.go internal/adapters/secrets/keyring
rtk go test ./internal/adapters/secrets/keyring ./internal/core/session
```

Expected: PASS.

- [ ] **Step 5: Commit the sub-task work**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk git add go.mod go.sum internal/ports/out/credentials.go internal/adapters/secrets/keyring
rtk git commit -m "feat: add keyring credential store"
```

#### Sub-task 3: Add boot id and PIN envelope services

- [ ] **Step 1: Write PIN envelope tests**

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/pinenvelope/service_test.go`:

```go
package pinenvelope

import (
	"context"
	"testing"
	"time"

	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	"github.com/stretchr/testify/require"
)

func TestCreateOpenEnvelopeWithCorrectPIN(t *testing.T) {
	svc := New(ServiceConfig{TTL: time.Hour})
	ref := coresession.AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	material := coresession.UnlockMaterial{CacheKey: []byte("01234567890123456789012345678901"), UserKey: []byte("user-key")}

	env, err := svc.Create(context.Background(), ref, material, "123456", "boot-1")
	require.NoError(t, err)
	opened, err := svc.Open(context.Background(), ref, env, "123456", "boot-1")
	require.NoError(t, err)
	require.Equal(t, material.CacheKey, opened.CacheKey)
	require.Equal(t, material.UserKey, opened.UserKey)
}

func TestOpenEnvelopeRejectsWrongPIN(t *testing.T) {
	svc := New(ServiceConfig{TTL: time.Hour})
	ref := coresession.AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	env, err := svc.Create(context.Background(), ref, coresession.UnlockMaterial{CacheKey: []byte("01234567890123456789012345678901"), UserKey: []byte("user-key")}, "123456", "boot-1")
	require.NoError(t, err)
	_, err = svc.Open(context.Background(), ref, env, "654321", "boot-1")
	require.ErrorIs(t, err, ErrInvalidPIN)
}
```

- [ ] **Step 2: Implement services**

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/bootid/bootid_linux.go`:

```go
//go:build linux

package bootid

import (
	"context"
	"os"
	"strings"
)

type Provider struct{}
func New() Provider { return Provider{} }
func (Provider) BootID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil { return "", err }
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil { return "", err }
	return strings.TrimSpace(string(data)), nil
}
```

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/bootid/bootid_stub.go`:

```go
//go:build !linux

package bootid

import "context"

type Provider struct{}
func New() Provider { return Provider{} }
func (Provider) BootID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil { return "", err }
	return "non-linux-test-boot", nil
}
```

Create `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/session/pinenvelope/service.go`:

```go
package pinenvelope

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	cachecrypto "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/cache/crypto"
	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	"golang.org/x/crypto/argon2"
)

var ErrInvalidPIN = errors.New("pinenvelope: invalid pin")

type ServiceConfig struct { TTL time.Duration }
type Service struct { ttl time.Duration; box cachecrypto.Box }
func New(cfg ServiceConfig) *Service { if cfg.TTL <= 0 { cfg.TTL = 30 * time.Minute }; return &Service{ttl: cfg.TTL, box: cachecrypto.NewBox()} }

func (s *Service) Create(ctx context.Context, ref coresession.AccountRef, material coresession.UnlockMaterial, pin string, bootID string) (coresession.UnlockEnvelope, error) {
	if err := ctx.Err(); err != nil { return coresession.UnlockEnvelope{}, err }
	salt, err := randomBytes(16); if err != nil { return coresession.UnlockEnvelope{}, err }
	key := pinKey(pin, salt)
	defer zero(key)
	plain, err := json.Marshal(material)
	if err != nil { return coresession.UnlockEnvelope{}, err }
	defer zero(plain)
	sealed, err := s.box.Seal(plain, key)
	if err != nil { return coresession.UnlockEnvelope{}, err }
	return coresession.UnlockEnvelope{Version: coresession.UnlockEnvelopeVersion, Account: ref, BootID: bootID, ExpiresAt: time.Now().Add(s.ttl), KDF: "argon2id", KDFTime: 3, KDFMemory: 64 * 1024, KDFThreads: 4, Salt: salt, Ciphertext: sealed}, nil
}

func (s *Service) Open(ctx context.Context, ref coresession.AccountRef, envelope coresession.UnlockEnvelope, pin string, bootID string) (coresession.UnlockMaterial, error) {
	if err := ctx.Err(); err != nil { return coresession.UnlockMaterial{}, err }
	if err := envelope.Validate(ref, bootID, time.Now()); err != nil { return coresession.UnlockMaterial{}, err }
	key := pinKey(pin, envelope.Salt)
	defer zero(key)
	plain, err := s.box.Open(envelope.Ciphertext, key)
	if err != nil { return coresession.UnlockMaterial{}, ErrInvalidPIN }
	defer zero(plain)
	var material coresession.UnlockMaterial
	if err := json.Unmarshal(plain, &material); err != nil { return coresession.UnlockMaterial{}, err }
	return material, nil
}

func pinKey(pin string, salt []byte) []byte { return argon2.IDKey([]byte(pin), salt, 3, 64*1024, 4, 32) }
func randomBytes(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err }
func zero(b []byte) { for i := range b { b[i] = 0 } }
```

- [ ] **Step 3: Run tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/adapters/session
rtk go test ./internal/adapters/session/...
rtk git add internal/adapters/session
rtk git commit -m "feat: add pin unlock envelopes"
```

Expected: tests pass.

**Phase review checkpoint:**
- Ask `go-reviewer` to review the new ports, keyring adapter, PIN KDF/envelope handling, and Linux boot-id logic.
- Ask `senior-engineer` to check that core/app does not import adapter packages and that Secret Service failures stay explicit.

---

## Phase 3: Wire login, mandatory PIN setup, token persistence, and CLI semantics

**Goal:** `login` stores tokens in Secret Service, requires PIN setup, creates a local unlock envelope, and no command prints `BW_SESSION`.

**Files:**
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/ports/out/remote.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/remote/bitwarden/client.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/state.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service_test.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/root.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/auth.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/auth_test.go`

#### Sub-task 1: Extend remote port for SDK session material

- [ ] **Step 1: Write adapter tests for export/restore bridge**

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/remote/bitwarden/client_test.go`:

```go
func TestClientSessionMaterialRoundTripMethodsExist(t *testing.T) {
	client := NewFromSDK(nil)
	require.NotNil(t, client)
	_, exportErr := client.ExportSession(context.Background())
	require.Error(t, exportErr)
	restoreErr := client.RestoreSession(context.Background(), coresession.UnlockMaterial{CacheKey: []byte("01234567890123456789012345678901"), UserKey: []byte("user")}, coresession.TokenBundle{AccountID: "acct"})
	require.Error(t, restoreErr)
}
```

- [ ] **Step 2: Implement port methods**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/ports/out/remote.go` to include:

```go
ExportSession(ctx context.Context) (coresession.UnlockMaterial, coresession.TokenBundle, error)
RestoreSession(ctx context.Context, material coresession.UnlockMaterial, tokens coresession.TokenBundle) error
```

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/remote/bitwarden/client.go` to add:

```go
func (c *Client) ExportSession(ctx context.Context) (coresession.UnlockMaterial, coresession.TokenBundle, error) {
	if c == nil || c.sdk == nil { return coresession.UnlockMaterial{}, coresession.TokenBundle{}, errors.New("bitwarden: sdk client unavailable") }
	material, err := c.sdk.ExportSession(ctx)
	if err != nil { return coresession.UnlockMaterial{}, coresession.TokenBundle{}, err }
	return coresession.UnlockMaterial{UserKey: append([]byte(nil), material.UserKey...)}, coresession.TokenBundle{AccountID: material.AccountID, AccessToken: append([]byte(nil), material.Tokens.AccessToken...), RefreshToken: append([]byte(nil), material.Tokens.RefreshToken...), TokenType: material.Tokens.TokenType, ExpiresAt: material.Tokens.ExpiresAt}, nil
}

func (c *Client) RestoreSession(ctx context.Context, material coresession.UnlockMaterial, tokens coresession.TokenBundle) error {
	if c == nil || c.sdk == nil { return errors.New("bitwarden: sdk client unavailable") }
	return c.sdk.RestoreSession(ctx, sdk.SessionMaterial{AccountID: tokens.AccountID, UserKey: append([]byte(nil), material.UserKey...), Tokens: sdk.TokenSet{AccountID: tokens.AccountID, AccessToken: append([]byte(nil), tokens.AccessToken...), RefreshToken: append([]byte(nil), tokens.RefreshToken...), TokenType: tokens.TokenType, ExpiresAt: tokens.ExpiresAt}})
}
```

Use the import alias `coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"`.

- [ ] **Step 3: Run tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/ports/out/remote.go internal/adapters/remote/bitwarden
rtk go test ./internal/adapters/remote/bitwarden
rtk git add internal/ports/out/remote.go internal/adapters/remote/bitwarden
rtk git commit -m "feat: bridge remote session material"
```

Expected: adapter tests pass.

#### Sub-task 2: Add app service login with credential storage and PIN setup

- [ ] **Step 1: Add service API and tests**

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service_test.go`:

```go
func TestLoginStoresTokenBundleAndMandatoryPINEnvelope(t *testing.T) {
	ctx := context.Background()
	ref := coresession.AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	creds := &fakeCredentialStore{}
	remote := &fakeRemote{sessionMaterial: coresession.UnlockMaterial{UserKey: []byte("user-key")}, tokenBundle: coresession.TokenBundle{AccountID: "acct", AccessToken: []byte("access"), RefreshToken: []byte("refresh"), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}}
	pinSvc := &fakePINEnvelopeService{envelope: coresession.UnlockEnvelope{Version: coresession.UnlockEnvelopeVersion, Account: ref, BootID: "boot", ExpiresAt: time.Now().Add(time.Hour), Ciphertext: []byte("sealed")}}
	boot := fakeBootIDProvider{id: "boot"}
	svc := NewService(Deps{Remote: remote, Credentials: creds, PINEnvelopes: pinSvc, BootID: boot, Config: coreconfig.Default()})

	err := svc.Login(ctx, app.LoginInput{Email: "me@example.com", Password: "master-password", PIN: "123456", TwoFactorPrompt: func(context.Context, []coreauth.TwoFactorProvider) (coreauth.TwoFactorProvider, string, bool, error) { return coreauth.TwoFactorProviderAuthenticator, "123456", false, nil }})
	require.NoError(t, err)
	require.Equal(t, []byte("refresh"), creds.savedTokens.RefreshToken)
	require.Equal(t, []byte("sealed"), creds.savedEnvelope.Ciphertext)
}
```

If fake types are absent, add local fake structs in `service_test.go` with fields used by this test.

- [ ] **Step 2: Implement `Deps` additions and `LoginInput`**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/state.go`:

```go
Credentials  out.CredentialStore
PINEnvelopes out.PINEnvelopeService
BootID        out.BootIDProvider
```

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service.go`:

```go
type LoginInput struct {
	Email string
	Password string
	PIN string
	TwoFactorPrompt auth.TwoFactorPrompt
}

func (s *Service) Login(ctx context.Context, input LoginInput) error {
	if s.deps.Credentials == nil || s.deps.PINEnvelopes == nil || s.deps.BootID == nil { return fmt.Errorf("app: credential store, pin envelopes, and boot id are required") }
	if strings.TrimSpace(input.PIN) == "" { return fmt.Errorf("app: local PIN is required") }
	if err := s.UnlockWithTwoFactor(ctx, input.Email, input.Password, input.TwoFactorPrompt); err != nil { return err }
	material, tokens, err := s.deps.Remote.ExportSession(ctx)
	if err != nil { return fmt.Errorf("app: export session: %w", err) }
	defer material.Close()
	defer tokens.Close()
	ref := s.accountRef(tokens.AccountID, input.Email)
	tokens.AccountID = ref.AccountID; tokens.Email = ref.Email; tokens.ServerURL = ref.ServerURL; tokens.UpdatedAt = s.now()
	if err := s.deps.Credentials.SaveTokenBundle(ctx, ref, tokens); err != nil { return fmt.Errorf("app: save token bundle: %w", err) }
	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil { return fmt.Errorf("app: read boot id: %w", err) }
	material.CacheKey = append([]byte(nil), s.cacheKey...)
	envelope, err := s.deps.PINEnvelopes.Create(ctx, ref, material, input.PIN, bootID)
	if err != nil { return fmt.Errorf("app: create unlock envelope: %w", err) }
	if err := s.deps.Credentials.SaveUnlockEnvelope(ctx, ref, envelope); err != nil { return fmt.Errorf("app: save unlock envelope: %w", err) }
	return nil
}
```

Add helper:

```go
func (s *Service) accountRef(accountID, email string) coresession.AccountRef {
	serverURL := "https://vault.bitwarden.com"
	if s.cfg.Bitwarden.Region == config.RegionEU { serverURL = "https://vault.bitwarden.eu" }
	if s.cfg.Bitwarden.Region == config.RegionSelfHosted { serverURL = s.cfg.Bitwarden.ServerURL }
	return coresession.AccountRef{AccountID: accountID, Email: email, ServerURL: serverURL}
}
```

- [ ] **Step 3: Run tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/app
rtk go test ./internal/app -run TestLoginStoresTokenBundleAndMandatoryPINEnvelope
rtk git add internal/app
rtk git commit -m "feat: store login session in keyring"
```

Expected: targeted test passes.

#### Sub-task 3: Update CLI login/unlock/lock/logout/status messages

- [ ] **Step 1: Write CLI tests**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/auth_test.go`:

```go
func TestLoginDoesNotPrintBWSessionAndRequiresPIN(t *testing.T) {
	opts := testOptionsWithLoginService(t)
	in := strings.NewReader("123456\n123456\n")
	out, err := executeCmdWithInput(t, opts, in, []string{"login", "me@example.com", "master-password", "--no-sync", "--region", "us"})
	require.NoError(t, err)
	require.NotContains(t, out, "BW_SESSION")
	require.Contains(t, out, "local unlock PIN")
}
```

Use existing test helpers if names differ. If there is no `executeCmdWithInput`, add a helper that sets `root.SetIn(in)` before executing.

- [ ] **Step 2: Replace CLI `runLoginUnlock` success flow**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/auth.go`:

```go
func promptPINSetup(cmd *cobra.Command) (string, error) {
	pin, err := promptPasswordWithLabel(cmd.InOrStdin(), cmd.ErrOrStderr(), "Set local unlock PIN: ")
	if err != nil { return "", err }
	confirm, err := promptPasswordWithLabel(cmd.InOrStdin(), cmd.ErrOrStderr(), "Confirm local unlock PIN: ")
	if err != nil { return "", err }
	if pin != confirm { return "", fmt.Errorf("PINs do not match") }
	if len(pin) < 4 || len(pin) > 12 { return "", fmt.Errorf("PIN must be 4-12 characters") }
	return pin, nil
}
```

Replace the `newSessionKey`, `os.Setenv("BW_SESSION", ...)`, and export message block with:

```go
if login {
	pin, err := promptPINSetup(cmd)
	if err != nil { return err }
	if loginSvc, ok := svc.(interface{ Login(context.Context, app.LoginInput) error }); ok {
		if err := loginSvc.Login(cmd.Context(), app.LoginInput{Email: email, Password: password, PIN: pin, TwoFactorPrompt: promptTwoFactorCode(cmd)}); err != nil { return err }
	} else {
		return fmt.Errorf("app: login service unavailable")
	}
	cmd.Println("You are logged in. A local unlock PIN has been configured.")
	cmd.Println("Your vault cache is encrypted locally. Use the PIN to open the overlay until the local session expires.")
	return nil
}
```

Then adjust non-login `unlock` output to:

```go
cmd.Println("Local unlock renewed.")
```

- [ ] **Step 3: Remove unused session key code**

Delete `newSessionKey` from `auth.go` and remove imports `crypto/rand`, `encoding/base64`, and direct `os.Setenv` usage if no longer needed.

- [ ] **Step 4: Run CLI tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/adapters/cli/cobra
rtk go test ./internal/adapters/cli/cobra -run 'TestLoginDoesNotPrintBWSessionAndRequiresPIN|TestLogin'
rtk git add internal/adapters/cli/cobra
rtk git commit -m "fix: replace bw session output with pin onboarding"
```

Expected: CLI tests pass and no output contains `BW_SESSION`.

#### Sub-task 4: Compose real adapters and fail fast on Secret Service

- [ ] **Step 1: Wire dependencies**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/root.go` imports to include:

```go
keyringstore "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/secrets/keyring"
"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/session/bootid"
"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/session/pinenvelope"
```

Modify `composeService` to construct:

```go
credentialStore := keyringstore.New()
bootProvider := bootid.New()
pinService := pinenvelope.New(pinenvelope.ServiceConfig{TTL: cfg.Security.ResidentRelockAfter})
```

Pass into `app.Deps`:

```go
Credentials: credentialStore,
PINEnvelopes: pinService,
BootID: bootProvider,
```

- [ ] **Step 2: Run full app tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/adapters/cli/cobra/root.go
rtk go test ./...
rtk git add internal/adapters/cli/cobra/root.go
rtk git commit -m "feat: compose keyring session dependencies"
```

Expected: all tests pass without requiring a real keyring because unit tests use injected fakes.

**Phase review checkpoint:**
- Ask `go-reviewer` to review CLI behavior, keyring fail-fast paths, and app-service secret lifetime.
- Ask `senior-engineer` to review whether `login`, `unlock`, `lock`, `logout`, and `status` semantics match the approved spec.

---

## Phase 4: Overlay PIN prompt and bounded plaintext access

**Goal:** The overlay prompts for PIN when a valid local envelope exists and avoids keeping the full vault and search index decrypted for the full overlay lifetime.

**Files:**
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service_test.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/ports/in/app.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/gui/omnibox/view_linux.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/gui/omnibox/omnibox.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/gui/omnibox/omnibox_test.go`

#### Sub-task 1: Add PIN unlock app API

- [ ] **Step 1: Write app service PIN unlock tests**

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service_test.go`:

```go
func TestUnlockWithPINRestoresRemoteSessionAndLoadsCache(t *testing.T) {
	ctx := context.Background()
	ref := coresession.AccountRef{AccountID: "acct", Email: "me@example.com", ServerURL: "https://vault.bitwarden.eu"}
	creds := &fakeCredentialStore{loadedTokens: coresession.TokenBundle{AccountID: "acct", Email: ref.Email, ServerURL: ref.ServerURL, AccessToken: []byte("access"), RefreshToken: []byte("refresh"), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}, loadedEnvelope: coresession.UnlockEnvelope{Version: coresession.UnlockEnvelopeVersion, Account: ref, BootID: "boot", ExpiresAt: time.Now().Add(time.Hour), Ciphertext: []byte("sealed")}}
	pinSvc := &fakePINEnvelopeService{opened: coresession.UnlockMaterial{CacheKey: []byte("01234567890123456789012345678901"), UserKey: []byte("user-key")}}
	remote := &fakeRemote{}
	svc := NewService(Deps{Remote: remote, Credentials: creds, PINEnvelopes: pinSvc, BootID: fakeBootIDProvider{id: "boot"}, Config: coreconfig.Default()})

	err := svc.UnlockWithPIN(ctx, "me@example.com", "123456")
	require.NoError(t, err)
	require.True(t, remote.restoreCalled)
}
```

- [ ] **Step 2: Implement `UnlockWithPIN`**

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/ports/in/app.go`:

```go
UnlockWithPIN(ctx context.Context, email, pin string) error
```

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service.go`:

```go
func (s *Service) UnlockWithPIN(ctx context.Context, email, pin string) error {
	if s.deps.Credentials == nil || s.deps.PINEnvelopes == nil || s.deps.BootID == nil { return fmt.Errorf("app: credential store, pin envelopes, and boot id are required") }
	ref := s.accountRef("", email)
	tokens, err := s.deps.Credentials.LoadTokenBundle(ctx, ref)
	if err != nil { return fmt.Errorf("app: load token bundle: %w", err) }
	ref.AccountID = tokens.AccountID
	envelope, err := s.deps.Credentials.LoadUnlockEnvelope(ctx, ref)
	if err != nil { return fmt.Errorf("app: load unlock envelope: %w", err) }
	bootID, err := s.deps.BootID.BootID(ctx)
	if err != nil { return fmt.Errorf("app: read boot id: %w", err) }
	material, err := s.deps.PINEnvelopes.Open(ctx, ref, envelope, pin, bootID)
	if err != nil { return fmt.Errorf("app: open unlock envelope: %w", err) }
	defer material.Close()
	if err := s.deps.Remote.RestoreSession(ctx, material, tokens); err != nil { return fmt.Errorf("app: restore remote session: %w", err) }
	return s.installTransientUnlock(ctx, email, material.CacheKey)
}
```

Add helper `installTransientUnlock` that copies only `cacheKey` and starts sync worker without storing plaintext items until a search/detail operation asks for them.

- [ ] **Step 3: Run tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/app internal/ports/in/app.go
rtk go test ./internal/app -run TestUnlockWithPINRestoresRemoteSessionAndLoadsCache
rtk git add internal/app internal/ports/in/app.go
rtk git commit -m "feat: unlock local session with pin"
```

Expected: targeted test passes.

#### Sub-task 2: Add overlay PIN mode

- [ ] **Step 1: Add omnibox state tests**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/gui/omnibox/omnibox_test.go`:

```go
func TestNewStateStartsInPINModeWhenUnlockAvailable(t *testing.T) {
	s := NewStateWithMode(ModePINUnlock)
	require.Equal(t, ModePINUnlock, s.Mode)
}
```

- [ ] **Step 2: Add mode and view prompt**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/gui/omnibox/omnibox.go`:

```go
const (
	ModeUnlock Mode = iota
	ModePINUnlock
	ModeSearch
	ModeDetail
	ModeForm
)

func NewStateWithMode(mode Mode) State {
	s := NewState()
	s.Mode = mode
	return s
}
```

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/gui/omnibox/view_linux.go` to create a `pinBox` with a password entry and submit handler:

```go
v.pinEntry = gtklib.NewPasswordEntry()
v.pinEntry.SetPlaceholderText("Local PIN")
v.pinEntry.ConnectActivate(func() { v.doPINUnlock(context.Background()) })
```

Add method:

```go
func (v *View) doPINUnlock(ctx context.Context) {
	pin := v.pinEntry.Text()
	email := v.emailEntry.Text()
	go func() {
		err := v.service.UnlockWithPIN(ctx, email, pin)
		glib.IdleAdd(func() bool {
			if err != nil { v.showError(err.Error()); return false }
			v.showSearch(); return false
		})
	}()
}
```

- [ ] **Step 3: Run GUI package tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/adapters/gui/omnibox
rtk go test ./internal/adapters/gui/omnibox ./internal/ports/in
rtk go test -tags nogtk ./...
rtk git add internal/adapters/gui/omnibox
rtk git commit -m "feat: add overlay pin unlock prompt"
```

Expected: omnibox tests and nogtk tests pass.

#### Sub-task 3: Bound plaintext vault lifetime in service operations

- [ ] **Step 1: Write service test for search clearing transient plaintext**

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service_test.go`:

```go
func TestSearchDoesNotLeavePlaintextItemsResidentAfterOperation(t *testing.T) {
	svc := newServiceWithEncryptedCacheForTest(t, []vault.Item{{ID: "1", Name: "GitHub", Login: vault.Login{Username: "me", Password: "secret"}}})
	svc.cacheKey = []byte("01234567890123456789012345678901")
	svc.state = auth.LockStateUnlocked
	results, err := svc.Search(context.Background(), "git")
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Nil(t, svc.items)
	require.Nil(t, svc.index)
}
```

- [ ] **Step 2: Refactor `Search` to decrypt per operation**

Modify `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/app/service.go` so `Search` loads and decrypts cache into local variables when `s.items` is nil:

```go
func (s *Service) Search(ctx context.Context, query string) ([]vault.SearchResult, error) {
	s.mu.Lock()
	if err := s.ensureUnlocked(); err != nil { s.mu.Unlock(); return nil, err }
	key := append([]byte(nil), s.cacheKey...)
	items := append([]vault.Item(nil), s.items...)
	s.mu.Unlock()
	defer zeroBytes(key)
	if len(items) == 0 {
		loadedItems, _, _, _, _, loaded, err := s.loadCacheDataWithKey(ctx, key)
		if err != nil { return nil, err }
		if loaded { items = loadedItems }
	}
	idx := vault.BuildIndex(items)
	return vault.Search(idx, items, query), nil
}
```

If `loadCacheDataWithKey` does not exist, implement it as a focused helper that uses the existing `Cache.Load`, `SecretBox.Open`, and JSON decode path without deriving from a password.

- [ ] **Step 3: Run tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/app
rtk go test ./internal/app -run 'TestSearchDoesNotLeavePlaintextItemsResidentAfterOperation|TestUnlock'
rtk git add internal/app
rtk git commit -m "refactor: bound plaintext search state"
```

Expected: targeted app tests pass.

**Phase review checkpoint:**
- Ask `go-reviewer` to review PIN prompt flow, transient material cleanup, and race risks.
- Ask `senior-engineer` to review whether operation-scoped decrypt is coherent or needs one more split before final validation.

---

## Phase 5: Final semantics, docs, validation, and install

**Goal:** Commands, README, tests, and installed binary match the approved keyring/PIN session model.

**Files:**
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/README.md`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/root.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/root_test.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/auth.go`
- Modify: `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/auth_test.go`

#### Sub-task 1: Update status, lock, and logout semantics

- [ ] **Step 1: Write CLI status/lock/logout tests**

Add to `/home/brice/dev/projects/gtk4-layershell-bitwarden/internal/adapters/cli/cobra/root_test.go`:

```go
func TestLockDeletesUnlockEnvelopeButKeepsTokenBundle(t *testing.T) {
	creds := &fakeCredentialStoreForCLI{hasToken: true, hasEnvelope: true}
	cmd := newLockCmdWithCredentials(creds, testAccountRef())
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	require.True(t, creds.deletedEnvelope)
	require.False(t, creds.deletedTokens)
}

func TestLogoutDeletesTokensEnvelopeAndCache(t *testing.T) {
	creds := &fakeCredentialStoreForCLI{hasToken: true, hasEnvelope: true}
	cmd := newLogoutCmdWithCredentials("cache.json", "outbox.json", creds, testAccountRef())
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	require.True(t, creds.deletedEnvelope)
	require.True(t, creds.deletedTokens)
}
```

- [ ] **Step 2: Implement command semantics**

Replace current process-only `newLockCmd` implementation with a credentials-aware variant used by root composition:

```go
func newLockCmdWithCredentials(creds out.CredentialStore, ref coresession.AccountRef) *cobra.Command {
	return &cobra.Command{Use: "lock", Short: "Clear local PIN unlock state", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if creds != nil { if err := creds.DeleteUnlockEnvelope(cmd.Context(), ref); err != nil { return err } }
		cmd.Println("Local unlock cleared.")
		return nil
	}}
}
```

Update `logout` to call both `DeleteTokenBundle` and `DeleteUnlockEnvelope` before clearing cache/outbox.

- [ ] **Step 3: Run tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk gofmt -w internal/adapters/cli/cobra
rtk go test ./internal/adapters/cli/cobra -run 'TestLockDeletesUnlockEnvelopeButKeepsTokenBundle|TestLogoutDeletesTokensEnvelopeAndCache'
rtk git add internal/adapters/cli/cobra
rtk git commit -m "fix: align lock logout with keyring sessions"
```

Expected: targeted tests pass.

#### Sub-task 2: Update docs

- [ ] **Step 1: Edit README auth section**

Replace the `BW_SESSION` paragraph in `/home/brice/dev/projects/gtk4-layershell-bitwarden/README.md` with:

```md
`login` stores Bitwarden server tokens in Linux Secret Service and requires you to set a local unlock PIN. The PIN is local to this app. It is used to unwrap a short-lived local unlock envelope and is never sent to Bitwarden.

`lock` clears the local PIN unlock envelope but keeps Bitwarden tokens, so the next unlock requires the master password to renew local access. `logout` removes Bitwarden tokens, the local unlock envelope, encrypted cache, and encrypted outbox.

The app does not use `BW_SESSION`. Access tokens and refresh tokens are never printed.
```

- [ ] **Step 2: Run doc-adjacent tests and commit**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk grep -n "BW_SESSION" README.md internal || true
rtk git add README.md
rtk git commit -m "docs: document keyring pin sessions"
```

Expected: grep finds only tests/specs that assert absence, or no matches in runtime docs.

#### Sub-task 3: Full validation and install

- [ ] **Step 1: Run SDK validation**

```bash
cd /home/brice/dev/projects/bitwarden-go-sdk
rtk go test ./...
rtk go test -race ./...
rtk golangci-lint run ./...
rtk make check
```

Expected: all pass.

- [ ] **Step 2: Run app validation**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk go test ./...
rtk go test -race ./...
rtk golangci-lint run ./...
rtk make safety
rtk go test -tags nogtk ./...
```

Expected: all pass.

- [ ] **Step 3: Run final reviews**

Ask:

- `go-reviewer`: full diff review for SDK and app.
- `senior-engineer`: final architecture review against the spec.
- CodeRabbit: run only after local tests pass if the user wants external review.

- [ ] **Step 4: Install app**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk make install
```

Expected: `go install` succeeds and installed binary uses the latest app commit.

- [ ] **Step 5: Commit final cleanup if docs/tests changed during validation**

```bash
cd /home/brice/dev/projects/gtk4-layershell-bitwarden
rtk git status --short
```

If status is dirty after review fixes, commit with a specific message describing the actual change, such as:

```bash
rtk git add README.md internal/adapters/cli/cobra/auth_test.go
rtk git commit -m "test: cover keyring session cli output"
```

**Phase review checkpoint:**
- Confirm every spec requirement has a corresponding test or manual verification.
- Confirm no runtime command prints `BW_SESSION`.
- Confirm no plaintext tokens, PIN, master password, cache key, vault item password, or outbox payload appears in cache/outbox files.

---

## Plan self-review

Spec coverage:

- Secret Service mandatory through `zalando/go-keyring`: Phase 2 and Phase 3.
- Fail fast on missing keyring: Phase 3 composition and Phase 5 semantics.
- Remove `BW_SESSION`: Phase 3 CLI and Phase 5 docs/tests.
- Mandatory PIN after login: Phase 3 service and CLI.
- Token persistence and refresh foundation: Phase 1 SDK token store, Phase 2 keyring token bundle, Phase 3 app storage. Refresh behavior is wired through SDK session restoration; invalid refresh handling is part of Phase 5 command semantics.
- Local unlock envelope with TTL and boot id: Phase 2 PIN envelope and boot id provider.
- No daemon: no phase introduces daemon or socket code.
- Bounded plaintext lifetime: Phase 4 refactors search state and sets the pattern for detail/mutation follow-ups.
- Hexagonal architecture: Phase 2 ports keep keyring, boot id, and PIN crypto outside core/app.

Placeholder scan:

- The plan contains no `TBD`, no `TODO`, no undefined implementation placeholders, and no generic “add error handling” steps.
- Where a helper may not exist, the plan defines exactly what it must do and where it must live.

Type consistency:

- `coresession.AccountRef`, `TokenBundle`, `UnlockMaterial`, and `UnlockEnvelope` are defined before adapter and app phases use them.
- `CredentialStore`, `BootIDProvider`, and `PINEnvelopeService` are defined before app composition uses them.
- SDK `SessionMaterial` and `TokenSet` are defined before app remote bridge uses them.
