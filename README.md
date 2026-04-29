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

(`$XDG_CONFIG_HOME` is respected if set.)

Start by copying the example config:

```
mkdir -p ~/.config/gtk4-layershell-bitwarden
cp configs/config.example.toml ~/.config/gtk4-layershell-bitwarden/config.toml
```

Minimum required setting: `bitwarden.email`.

A missing config file is **not** an error — built-in defaults are used and
the config can be written later through the GUI.

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

- **Encrypted cache**: The vault snapshot and outbox are stored on disk
  encrypted with a key derived from the master password (SHA-256). See
  `internal/adapters/cache/`.
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
