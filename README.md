# gtk4-layershell-bitwarden

A **overlay-only** GTK4 layer-shell Bitwarden client for Linux desktop
environments using the wlr-layer-shell protocol.

The application runs as a keyboard-driven overlay over your compositor — it
does **not** open a regular window. It is designed for quick vault search,
copy, and edit workflows without leaving your current workspace.

---

## Status

**v0.1.0 — daily-usable goal, local development branch**

This version targets daily-usable functionality but lives on the
`feat/v0.1.0` branch for local testing. It is not yet tagged for general
consumption. Expect rough edges and breaking changes as the API stabilises.

---

## Local SDK Replacement

The project depends on a local fork of the Bitwarden Go SDK, resolved via
a `replace` directive in `go.mod`:

```
replace github.com/bnema/bitwarden-go-sdk => ../bitwarden-go-sdk
```

The SDK repository at `../bitwarden-go-sdk` is expected to carry tag `v0.1.0`.
If you clone the repositories side by side, no manual `replace` change is
needed.

---

## Build / Install Requirements

| Dependency | Version / Notes |
|---|---|
| **Go** | `1.26.1` or later |
| **GTK4** | Development headers (`libgtk-4-dev` or equivalent) |
| **gtk4-layer-shell** | Development headers |
| **Compositor** | Wayland compositor with `wlr-layer-shell` support (e.g. Sway, Hyprland) |

### Headless builds

Unit tests and code that does not depend on GTK can be compiled and run
without a display server by passing the `nogtk` build tag:

```
go test -tags nogtk ./...
```

This excludes the GTK/layer-shell GUI adapter from compilation.

---

## First Run / Config

On first run the application looks for a configuration file at:

```
~/.config/gtk4-layershell-bitwarden/config.toml
```

(`$XDG_CONFIG_HOME` is respected if set; falls back to `os.UserConfigDir()`
and finally to `./gtk4-layershell-bitwarden/config.toml` as a last resort.)

Start by copying the example config:

```
mkdir -p ~/.config/gtk4-layershell-bitwarden
cp configs/config.example.toml ~/.config/gtk4-layershell-bitwarden/config.toml
```

Minimum required setting for non-interactive unlock: `bitwarden.email`.

A missing config file is **not** an error — built-in defaults are used and
the config can be written later through the CLI or GUI.

---

## Login / Unlock CLI Flow

The CLI mirrors the official Bitwarden CLI shape for local auth commands:

```sh
gtk4-layershell-bitwarden login you@example.com --region us
gtk4-layershell-bitwarden login you@example.com --region eu
gtk4-layershell-bitwarden login you@example.com --region self_hosted --server-url https://vault.example.com
gtk4-layershell-bitwarden unlock
gtk4-layershell-bitwarden status
gtk4-layershell-bitwarden lock
gtk4-layershell-bitwarden logout
```

`login` prompts for missing email, region (`us`, `eu`, or `self_hosted`),
self-hosted server URL when needed, and master password. It authenticates with
Bitwarden, stores the email/region/server URL in config, runs initial sync, and
writes the encrypted cache/outbox under the XDG cache directory. `login` stores
Bitwarden server tokens (access token, refresh token) in the Linux Secret Service
keyring and requires a local unlock PIN. The PIN unwraps a short-lived local
unlock envelope and is never sent to Bitwarden. Secret Service is mandatory on
Linux; if unavailable, auth commands fail with a `keyring_unavailable` error.

`unlock` uses the configured email/region and prompts for the local PIN. If the
local unlock envelope is missing, expired, or deleted after too many failed PIN
attempts, run `login` again with the Bitwarden master password to create a new
PIN envelope.

Note for headless/CI environments: Secret Service depends on a running desktop
session with a D-Bus session bus and a keyring daemon such as GNOME Keyring or
KWallet. Headless servers, containers, and CI pipelines typically lack this
infrastructure and will see `keyring_unavailable` errors. In those environments,
run a compatible keyring service or use a different auth strategy outside this
local desktop client.

`lock` clears the local PIN unlock envelope from the keyring but keeps
Bitwarden tokens intact.

`logout` removes Bitwarden tokens, the local unlock envelope, the encrypted
cache, and the encrypted outbox from disk.

All auth commands support:

```sh
--raw                 # print minimal output ("login ok" or "unlock ok")
--passwordenv NAME    # read master password from an environment variable
--passwordfile PATH   # read master password from a file
--no-sync             # authenticate/unlock without waiting for initial sync
```

The app does **not** use the `BW_SESSION` environment variable. Access tokens,
refresh tokens, PINs, and vault keys are never printed to stdout or stderr.

On Wayland, the launcher re-execs itself with `libgtk4-layer-shell.so.0` in
`LD_PRELOAD` before GTK initializes. This matches the sekeve bootstrap and is
needed on compositors such as Niri where gtk4-layer-shell's GDK hook must be
loaded before GTK. If the GTK overlay is still launched outside a layer-shell-
capable Wayland session, the command exits with guidance to use `login`,
`unlock`, or `status` from the terminal instead.

---

## Environment Overrides

All config keys can be overridden through environment variables with the
prefix `GLSBW_` and dots replaced by underscores.

| Environment variable | Config key |
|---|---|
| `GLSBW_BITWARDEN_EMAIL` | `bitwarden.email` |
| `GLSBW_BITWARDEN_REGION` | `bitwarden.region` |
| `GLSBW_SYNC_REVISION_CHECK_INTERVAL` | `sync.revision_check_interval` |
| `GLSBW_SECURITY_IDLE_RELOCK_AFTER` | `security.idle_relock_after` |
| `GLSBW_ACTIONS_CLIPBOARD_CLEAR_AFTER` | `actions.clipboard_clear_after` |
| `GLSBW_APPEARANCE_UI_SCALE` | `appearance.ui_scale` |
| `GLSBW_CACHE_TTL` | `cache.ttl` |

Environment overrides are **always** active and take precedence over the
config file.

---

## Compositor Hotkey

Bind a compositor hotkey to launch the overlay. Example for Sway:

```
# ~/.config/sway/config
bindsym $mod+Shift+b exec /path/to/gtk4-layershell-bitwarden
```

The overlay window uses the layer-shell protocol and requests exclusive
keyboard focus, so it will capture input until dismissed.

---

## Keyboard Shortcuts

| Shortcut | Context | Action |
|---|---|---|
| `Enter` (on unlock) | Unlock | Authenticates with email + master password |
| (typing) | Search | Live search with debounce (150 ms) |
| `Up` / `Down` | Search | Navigate through result rows |
| `Enter` | Search | Perform **primary action** on selected row (see `[actions]` config) |
| `Ctrl` + `Enter` | Search | Open detail view for the selected row |
| `Ctrl` + `N` | Search | Create a new login item |
| `Escape` | Any | Quit the overlay |
| `Escape` / `Backspace` | Detail / Form | Return to search view |
| Click buttons | Detail / Form | Edit, Save, Trash, Restore, Delete permanently |

**Copy actions status**: The primary action `copy_password` and
`copy_username` currently **set an in-app status indicator** ("Password
copied" / "Username copied") but do **not** yet call the system clipboard.
The clipboard adapter exists in the codebase but is not wired to the GUI
primary action pipeline as of Phase 6. `open_url` is also not wired yet
and falls back to `copy_password`. These will be addressed in a follow-up
phase.

---

## Cache and Security Model

- **File paths**: All XDG paths are centralized in
  `internal/adapters/paths/xdg/`. Config, cache, outbox, and state/log paths
  are derived from the same adapter:
  - **Config**: `$XDG_CONFIG_HOME/gtk4-layershell-bitwarden/config.toml` —
    falls back to `os.UserConfigDir()`, then `./`.
  - **Cache / Outbox**: `$XDG_CACHE_HOME/gtk4-layershell-bitwarden/{cache,outbox}.json` —
    falls back to `os.UserCacheDir()`, then `os.TempDir()`.
  - **State / Log**: `$XDG_STATE_HOME/gtk4-layershell-bitwarden/` —
    falls back to `$HOME/.local/state/`, then `os.TempDir()/state/`.
    A `LogFile()` path helper exists for future use; the current logger
    defaults to discard unless injected.
- **Encrypted cache**: The vault snapshot and outbox are stored on disk
  encrypted with a key derived from the master password using Argon2id and a
  persisted per-cache salt. See `internal/adapters/cache/`.
- **No plaintext search index**: The in-memory search index (`vault.BuildIndex`)
  is never written to disk. On relock it is dropped.
- **File permissions**: Config directory is created with `0700`, config file
  with `0600`. Cache files use the same restrictive permissions.
- **No HTTP body dumps**: The codebase is checked by `make safety` for
  accidental HTTP body-dump patterns (HTTP utility request/response
  dumping, token leakage, or plaintext password in command lines).
- **No secret logging**: Passwords, tokens, and vault content are never
  written to logs.

---

## Offline-First Sync / Outbox / Conflicts

- Mutations (create, update, trash, restore, delete) are attempted against
  the remote server first. If the server is unreachable the mutation is
  queued locally in an **outbox** (`internal/core/sync/types.go`) and
  persisted in encrypted form.
- On the next successful sync the outbox is replayed against the server.
- If a conflict is detected (local mutation + remote change for the same
  item), the application emits a `ConflictDetected` event and marks the
  item with a conflict badge. Resolution strategies (keep remote, keep
  local, duplicate) are available through `ResolveConflict`.
- The outbox stores mutations **by ID** and deduplicates them on load.

---

## Testing

```
# All unit tests (excluding GTK-dependent code)
go test -tags nogtk ./...

# Race detection
go test -race -tags nogtk ./...

# Safety checks (secret leakage, unexpected disk writes)
make safety

# Full check suite (test + lint + safety)
make check
```

### Dependency policy

External dependencies are fetched with:

```
go get <module>@latest
```

No vendoring or `go mod vendor` is used. The SDK fork is resolved by the
`replace` directive in `go.mod`.

### Note about live tests

No tests run against a live Bitwarden server by default. All tests operate
on in-memory or local isolated data.

### Forked dependency: `github.com/bnema/purego`

`github.com/bnema/puregotk` (v0.5.1) transitively pulls a fork of the
[cgo-free FFI library `purego`](https://github.com/ebitengine/purego) from
`github.com/bnema/purego` (v0.11.0-bnema.2). This fork includes patches
necessary for Wayland/GTK4 layer-shell support that are not yet upstream.

The version is pinned by `puregotk`'s `go.mod` and is not directly
required in this project's `go.mod`. The fork is maintained by the same
organisation that maintains `puregotk`. No `replace` directive is needed;
the version is resolved transitively. If the patches are merged upstream,
the dependency can be switched back to the official `github.com/ebitengine/purego`.

---

## Known Limitations

- **Attachments**: `ListAttachments`, `DownloadAttachment`, `UploadAttachment`,
  and `DeleteAttachment` all return `ErrUnsupported` from the application
  service (`internal/app/service.go`). Attachment support is planned for a
  future phase.
- **Clipboard integration**: The clipboard TTL-based adapter exists
  (`internal/adapters/clipboard/`) but is not yet wired into the GTK
  overlay's primary action flow (`doPrimaryAction` in
  `internal/adapters/gui/omnibox/view_linux.go`). Copy actions currently
  display an in-app status message without touching the system clipboard.
- **open_url default**: The `default_primary_action = "open_url"` config
  value is accepted by validation but not yet wired in the GUI; it falls
  back to `copy_password`.
- **Conflict resolution UX**: The conflict resolution functions exist in
  the service layer but are not yet surfaced through the GUI detail view.
- **Form editing**: Editing existing items is supported, but adding custom
  fields is not yet available in the form.

## License

MIT
