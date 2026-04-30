# gtk4-layershell-bitwarden keyring, PIN, and local session design

Date: 2026-04-28
Status: proposed

## Decision summary

Use Linux Secret Service as a mandatory credential store through `github.com/zalando/go-keyring`. If Secret Service is unavailable, locked in a way the app cannot use, or returns an unexpected error, authentication commands fail fast with a clear setup message.

Remove the current placeholder `BW_SESSION` behavior. It is not a Bitwarden server token and should not be presented as a required user action.

Do not add a daemon for this iteration. The app uses process-local memory and Secret Service state. Each CLI or overlay process can read stored Bitwarden tokens, refresh them when needed, and request a local unlock PIN or master password depending on the local session envelope state.

Make local PIN setup mandatory after a successful Bitwarden login. The PIN is a local unlock factor, not a Bitwarden credential. It never leaves the machine and is never sent to Bitwarden.

Do not keep the vault decrypted for the lifetime of the overlay. Decrypt only for the current operation or short UI interaction, return the minimum data needed, and clear transient plaintext and keys as soon as practical.

## Goals

- Store Bitwarden access and refresh tokens in Secret Service instead of plaintext files or process-only placeholders.
- Refresh Bitwarden access tokens automatically when possible.
- Keep master password and TOTP codes out of persistent storage and logs.
- Provide a fast overlay unlock path with a mandatory local PIN after the user has completed `login` once.
- Expire local unlock state after a configurable TTL and across reboot.
- Preserve the hexagonal architecture: core/app code depends on ports, while Secret Service and CLI/GTK details stay in adapters.
- Make `login`, `lock`, `logout`, `status`, and overlay startup semantics clear.

## Non-goals

- No daemon, socket protocol, systemd user service, or cross-process resident vault state in this iteration.
- No support for Windows or macOS keychains.
- No fallback to `pass`, plaintext files, or environment variables for persisted tokens.
- No storage of the Bitwarden master password.
- No persistent plaintext vault cache, plaintext outbox, or plaintext search index.
- No promise of perfect Go heap zeroization for strings already passed to UI/toolkit code. The goal is to minimize plaintext lifetime and copies.

## Secret model

### Secret Service token bundle

Secret Service stores a Bitwarden token bundle per account/server:

- account id
- email
- region or server URL
- access token
- refresh token
- token type
- access token expiry
- token update time

The token bundle is a server-authentication secret. It lets the app call Bitwarden APIs until the refresh token is revoked or expires. It does not decrypt the local vault cache by itself.

### Local unlock envelope

Secret Service also stores a local unlock envelope per account/server. The envelope contains a cache unlock key encrypted under a key derived from the local PIN.

Envelope contents:

- account id
- email
- region/server identity
- boot id fingerprint
- expires at
- PIN KDF parameters and salt
- nonce
- encrypted local cache unlock key
- optional PIN verifier metadata

The local cache unlock key is high entropy or derived from the master-password-authenticated cache key. It is the secret that lets the current process decrypt the local encrypted cache without asking for the master password again. It must be wrapped by the PIN before storage; do not store the raw cache key in Secret Service.

The envelope is valid only when:

- current time is before `expires_at`
- current Linux boot id matches the envelope boot id
- account/server identity matches the current config
- PIN unwrap succeeds

Default local unlock TTL: `30m`, using existing `security.resident_relock_after` or a new clearer setting such as `security.local_unlock_ttl`. The exact config name can be finalized in the implementation plan.

### PIN security limitations

A short PIN is not as strong as the master password. The design relies on layered controls:

- Secret Service protects access to the envelope.
- The PIN wraps the local cache unlock key so a same-user process cannot use the raw key unless it can also unlock the envelope.
- Argon2id makes PIN guessing more expensive.
- The envelope expires by TTL and reboot.
- Failed PIN attempts use local backoff and can delete the envelope after repeated failures.

Because app-side rate limiting can be bypassed by a process that can exfiltrate the envelope from Secret Service, the PIN is a pragmatic local UX factor, not a replacement for the master password under full local-user compromise.

## User flows

### First `login`

1. Fail fast if Secret Service is unavailable.
2. Prompt for email, region/server URL, master password, and Bitwarden 2FA when required.
3. Authenticate with Bitwarden.
4. Store the Bitwarden token bundle in Secret Service.
5. Sync the vault and write only encrypted cache/outbox data to disk.
6. Prompt for mandatory local PIN setup and confirmation.
7. Create and store a local unlock envelope in Secret Service.
8. Print a concise success message. Do not print `BW_SESSION`.

Success message example:

```text
You are logged in. A local unlock PIN has been configured.
Your vault cache is encrypted locally. Use the PIN to open the overlay until the local session expires.
```

### Overlay startup

1. Fail fast with setup guidance if Secret Service is unavailable.
2. Load config and look for a token bundle.
3. If no token bundle exists, show login/onboarding UI.
4. If a token bundle exists, refresh the Bitwarden access token when expired or close to expiry.
5. If a valid local unlock envelope exists, show a compact PIN prompt, similar to sekeve.
6. If the PIN unwrap succeeds, decrypt only the data needed for the current UI operation.
7. If no valid envelope exists, show a master password prompt. After successful cache unlock, require PIN entry or reset to create a fresh envelope.
8. Clear transient keys and plaintext when the overlay closes, locks, or completes sensitive operations.

### Operation-scoped vault access

Search and item-detail access should not install a long-lived plaintext vault in app state.

Preferred behavior:

1. Obtain a cache unlock key from the current operation context.
2. Load encrypted cache.
3. Decrypt into short-lived local variables.
4. Build search results or detail view data for the current UI request.
5. Clear plaintext slices/keys where possible.
6. Do not persist plaintext indexes.

A short-lived in-memory interaction window is acceptable for a focused overlay session, but it should be bounded by explicit close/lock, idle timeout, and operation completion. The implementation should avoid the current model where the whole vault and search index remain resident indefinitely after unlock.

### `unlock`

`unlock` becomes a local-session renewal command, not a Bitwarden login command.

- If a valid token bundle exists and the cache can be opened with the master password, `unlock` creates a fresh PIN-wrapped local unlock envelope.
- If the token bundle is expired, `unlock` refreshes it first.
- If refresh fails, the user must run `login` again.
- `unlock` should not print `BW_SESSION`.

### `lock`

`lock` deletes the local unlock envelope and clears any process memory state.

It does not delete Bitwarden token bundles. After `lock`, the user remains logged in to Bitwarden from the app's perspective, but must enter the master password to create a new local unlock envelope.

### `logout`

`logout` removes all local authentication state for the account/server:

- Bitwarden token bundle from Secret Service
- local unlock envelope from Secret Service
- cached PIN verifier/envelope metadata
- encrypted cache and outbox, unless an implementation-time option deliberately keeps cache data

Default behavior should favor safety: delete tokens, local unlock envelope, cache, and outbox.

### `status`

`status` should stop implying that a process-local `BW_SESSION` matters. It can report:

- `unauthenticated`: no token bundle
- `logged_in_locked`: token bundle exists, no valid local unlock envelope
- `logged_in_unlock_available`: valid envelope exists, PIN can be prompted
- `keyring_unavailable`: Secret Service unavailable

Do not print token contents, envelope contents, or cache keys.

## Architecture

### Core/app ports

Add ports that express app needs without importing keyring or D-Bus types into core/app layers.

Candidate ports:

```go
type CredentialStore interface {
    SaveTokenBundle(ctx context.Context, ref AccountRef, bundle TokenBundle) error
    LoadTokenBundle(ctx context.Context, ref AccountRef) (TokenBundle, error)
    DeleteTokenBundle(ctx context.Context, ref AccountRef) error

    SaveUnlockEnvelope(ctx context.Context, ref AccountRef, envelope UnlockEnvelope) error
    LoadUnlockEnvelope(ctx context.Context, ref AccountRef) (UnlockEnvelope, error)
    DeleteUnlockEnvelope(ctx context.Context, ref AccountRef) error
}

type LocalUnlockService interface {
    CreateEnvelope(ctx context.Context, input CreateEnvelopeInput) (UnlockEnvelope, error)
    OpenEnvelope(ctx context.Context, envelope UnlockEnvelope, pin string) (CacheUnlockKey, error)
}
```

Exact names can change, but the dependency direction must remain:

```text
core/app -> ports -> adapters/secrets/keyring
```

### Secret Service adapter

Implement `internal/adapters/secrets/keyring` with `github.com/zalando/go-keyring`.

Service names should be stable and account/server scoped, for example:

- `gtk4-layershell-bitwarden/token/<account-or-email>/<server-hash>`
- `gtk4-layershell-bitwarden/unlock/<account-or-email>/<server-hash>`

The adapter serializes token bundles and unlock envelopes as JSON before storing the secret string. Serialization must not be logged.

### Token refresh integration

The app should use the SDK token refresh capability when an access token is expired or near expiry. After refresh, it saves the new token bundle back to Secret Service.

The app should treat refresh failure as an authentication boundary:

- invalid/expired refresh token -> delete stale token bundle and require `login`
- transient network failure -> preserve token bundle, show offline-capable status if cache access is possible

### Cache encryption integration

The existing encrypted cache can remain, but the service must stop assuming a long-lived unlocked state. Refactor toward operation-scoped APIs:

- open cache for search
- open cache for item detail
- open cache for mutation/outbox update
- close/clear transient state

If implementation needs an intermediate step, bound the lifetime with idle timeout and explicit lock while preserving the final target of operation-scoped decryption.

## Configuration

Required or proposed settings:

- `security.local_unlock_ttl`: default `30m`
- `security.pin_min_length`: default `4` or `6`; final value should balance sekeve-like UX and brute-force cost
- `security.pin_max_failures`: default `5`
- `security.pin_backoff`: exponential, capped

Existing `security.idle_relock_after` and `security.resident_relock_after` should either be mapped to these concepts or renamed in a migration-safe way.

## Error handling and UX

Secret Service unavailable:

```text
Secret Service is required for gtk4-layershell-bitwarden authentication state.
Start GNOME Keyring, KWallet, or a compatible Secret Service provider, then retry.
```

PIN wrong:

```text
Incorrect PIN.
```

PIN too many failures:

```text
Too many PIN attempts. Local unlock was cleared; enter your master password to unlock again.
```

Local session expired:

```text
Local unlock expired. Enter your master password to renew it.
```

Refresh token invalid:

```text
Bitwarden login expired. Run login again.
```

## Testing strategy

- Unit tests for PIN envelope creation/opening, TTL expiry, boot id mismatch, wrong PIN, and repeated failure behavior.
- Unit tests for Secret Service adapter using an interface seam around `go-keyring` so tests do not require a real keyring.
- App service tests for login creating token bundle and mandatory PIN envelope.
- App service tests for overlay startup paths: no token, token only, valid envelope, expired envelope, keyring unavailable.
- CLI tests proving `BW_SESSION` is no longer printed.
- Integration tests confirming encrypted cache/outbox files do not contain vault plaintext, tokens, PIN, or cache keys.
- Race tests around lock while operation-scoped decrypt/search is in flight.

## Rollout plan

1. Add CredentialStore and local unlock envelope domain types behind ports.
2. Add keyring adapter and fail-fast availability check.
3. Move Bitwarden token persistence into Secret Service.
4. Remove `BW_SESSION` generation and messaging.
5. Add mandatory PIN setup after successful login.
6. Add PIN prompt path to CLI/overlay startup.
7. Refactor vault access away from indefinite resident plaintext toward operation-scoped decrypt.
8. Update README and status/lock/logout semantics.

## Spec self-review

- No TBD placeholders remain.
- The design is Linux-only and intentionally uses Secret Service as a hard requirement.
- The design distinguishes Bitwarden server tokens from local unlock secrets.
- The design does not store master passwords, plaintext vault data, plaintext indexes, raw cache keys, or `BW_SESSION` equivalents.
- The PIN limitation is explicit: it improves UX and adds a local gate, but it is not equivalent to the master password under full local-user compromise.
- The design fits the existing hexagonal package layout by using ports and adapters.
