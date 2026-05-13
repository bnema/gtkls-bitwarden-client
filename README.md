# gtk4-layershell-bitwarden

A keyboard-driven GTK4 layer-shell Bitwarden client for Linux Wayland desktops.

The app runs as an overlay over your compositor instead of a regular window. It is built for fast vault search, copy-oriented workflows, and lightweight item editing without leaving the current workspace.

## Status

**v0.1.0 — early public release**

This release is intended for Linux desktop users who are comfortable with early software. The core login, quick unlock, encrypted cache, search, and item edit flows are usable, but some UI workflows are still incomplete. Expect breaking changes before a stable v1.0 release.

## Build / Install Requirements

| Dependency | Version / Notes |
|---|---|
| **Go** | `1.26.1` or later |
| **GTK4** | Runtime libraries for GTK4 |
| **gtk4-layer-shell** | Runtime library providing `libgtk4-layer-shell.so.0` |
| **Compositor** | Wayland compositor with `wlr-layer-shell` support, such as Sway or Hyprland |
| **Secret Service** | Linux Secret Service keyring, such as GNOME Keyring or KWallet |

Build from source:

```sh
git clone https://github.com/bnema/gtk4-layershell-bitwarden.git
cd gtk4-layershell-bitwarden
make build
./dist/gtk4-layershell-bitwarden --version
```

Install with Go once the repository is published and tagged:

```sh
go install github.com/bnema/gtk4-layershell-bitwarden/cmd/gtk4-layershell-bitwarden@v0.1.0
```

Headless tests and non-GTK code can be built with the `nogtk` build tag:

```sh
go test -tags nogtk ./...
```

## First Run / Config

The default config path is:

```sh
~/.config/gtk4-layershell-bitwarden/config.toml
```

`$XDG_CONFIG_HOME` is respected. A missing config file is not an error; built-in defaults are used and the config can be written later through the CLI or GUI.

Optional starter config:

```sh
mkdir -p ~/.config/gtk4-layershell-bitwarden
cp configs/config.example.toml ~/.config/gtk4-layershell-bitwarden/config.toml
```

For non-interactive unlock flows, configure `bitwarden.email` first:

```sh
gtk4-layershell-bitwarden config set bitwarden.email you@example.com
```

## Login / Unlock CLI Flow

Common commands:

```sh
gtk4-layershell-bitwarden login you@example.com --region us
gtk4-layershell-bitwarden login you@example.com --region eu
gtk4-layershell-bitwarden login you@example.com --region self_hosted --server-url https://vault.example.com
gtk4-layershell-bitwarden unlock
gtk4-layershell-bitwarden status
gtk4-layershell-bitwarden lock
gtk4-layershell-bitwarden lock --hard
gtk4-layershell-bitwarden logout
```

`login` prompts for missing email, region (`us`, `eu`, or `self_hosted`), self-hosted server URL when needed, master password, and a local unlock PIN with confirmation. It authenticates with Bitwarden, stores account config, runs initial sync unless `--no-sync` is set, and writes encrypted cache/outbox files under the XDG cache directory.

`unlock` uses the configured account and asks for the local PIN when a boot-bound quick-unlock envelope is available. When background sync is enabled, a successful PIN unlock refreshes the encrypted cache asynchronously without installing a long-lived resident plaintext vault. If the envelope is missing or invalid, run `login` again with the Bitwarden master password to recreate quick unlock.

`lock` is a soft lock by default: it clears resident process state and keeps credentials, the quick-unlock envelope, encrypted cache, and encrypted outbox. Closing the overlay also performs this soft-lock step before GTK exits. `lock --hard` deletes only the quick-unlock envelope while keeping the token bundle and PIN profile.

`logout` removes Bitwarden tokens, the PIN profile, the quick-unlock envelope, encrypted cache, encrypted outbox, and local account identity config. The next `login` prompts for email again.

Auth flags:

```sh
--raw                 # print minimal output, such as "login ok" or "unlock ok"
--no-sync             # authenticate/unlock without waiting for initial sync
--passwordenv NAME    # login: read master password from an environment variable
--passwordfile PATH   # login: read master password from a file
--pinenv NAME         # unlock: read local PIN from an environment variable
--pinfile PATH        # unlock: read local PIN from a file
```

For backward compatibility, `unlock` also accepts `--passwordenv` and `--passwordfile` as legacy aliases for PIN input. Prefer `--pinenv` and `--pinfile` for new scripts.

The app does **not** use the `BW_SESSION` environment variable. Access tokens, refresh tokens, raw PINs, vault keys, and vault content are never printed to stdout or stderr.

Headless servers, containers, and CI usually do not have a D-Bus session bus plus Secret Service provider. Auth commands in those environments typically fail with `keyring_unavailable`.

## Environment Overrides

All config keys can be overridden through environment variables with the `GLSBW_` prefix and dots replaced by underscores.

| Environment variable | Config key |
|---|---|
| `GLSBW_BITWARDEN_EMAIL` | `bitwarden.email` |
| `GLSBW_BITWARDEN_REGION` | `bitwarden.region` |
| `GLSBW_BITWARDEN_SERVER_URL` | `bitwarden.server_url` |
| `GLSBW_DEVICE_IDENTIFIER` | `device.identifier` |
| `GLSBW_SYNC_REVISION_CHECK_INTERVAL` | `sync.revision_check_interval` |
| `GLSBW_SECURITY_IDLE_RELOCK_AFTER` | `security.idle_relock_after` |
| `GLSBW_SECURITY_RESIDENT_RELOCK_AFTER` | `security.resident_relock_after` |
| `GLSBW_ACTIONS_CLIPBOARD_CLEAR_AFTER` | `actions.clipboard_clear_after` |
| `GLSBW_APPEARANCE_UI_SCALE` | `appearance.ui_scale` |
| `GLSBW_CACHE_TTL` | `cache.ttl` |

Environment overrides take precedence over the config file.

## Logging

Logs are written to a rotating file by default:

```sh
$XDG_STATE_HOME/gtk4-layershell-bitwarden/logs/gtk4-layershell-bitwarden.log
```

If `$XDG_STATE_HOME` is unset, Linux defaults to:

```sh
~/.local/state/gtk4-layershell-bitwarden/logs/gtk4-layershell-bitwarden.log
```

Default logging is file-only, level `info`, and JSON formatted. Set `GLSBW_LOG_CONSOLE=true` to mirror logs to stderr.

| Environment variable | Purpose |
|---|---|
| `GLSBW_LOG_LEVEL` | `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal`, `panic`, or `disabled` |
| `GLSBW_LOG_FORMAT` | `json` or `console` |
| `GLSBW_LOG_CONSOLE` | Mirror logs to stderr when `true` |
| `GLSBW_LOG_PATH` | Override log file path |
| `GLSBW_LOG_MAX_SIZE_MB` | Rotate after this many MiB |
| `GLSBW_LOG_MAX_BACKUPS` | Number of rotated backups to keep |
| `GLSBW_LOG_MAX_AGE_DAYS` | Maximum age of rotated logs in days |

Invalid logging environment values fail startup with a clear error naming the invalid variable. The project follows a strict no-secret logging policy.

## Compositor Hotkey

Bind a compositor hotkey to launch the overlay. Example for Sway:

```sh
# ~/.config/sway/config
bindsym $mod+Shift+b exec /path/to/gtk4-layershell-bitwarden
```

On Wayland, the launcher re-execs itself with `libgtk4-layer-shell.so.0` in `LD_PRELOAD` before GTK initializes. This is required on compositors where gtk4-layer-shell's GDK hook must load before GTK.

## Keyboard Shortcuts

| Shortcut | Context | Action |
|---|---|---|
| `Enter` on unlock | Unlock | Authenticates with local PIN or master-password recovery flow |
| typing | Search | Live search with debounce |
| `Up` / `Down` | Search | Navigate result rows |
| `Enter` | Search | Perform configured primary action |
| `Ctrl` + `Enter` | Search | Open detail view |
| `Ctrl` + `N` | Search | Create a new login item |
| `Escape` | Any | Quit the overlay |
| `Escape` / `Backspace` | Detail / Form | Return to search view |

In v0.1.0, `copy_password` and `copy_username` write to the system clipboard through the GTK/GDK clipboard and then update the in-app status indicator. `open_url` is accepted by config validation but currently falls back to `copy_password`.

## Cache and Security Model

- **XDG paths**: config, cache, outbox, state, and log paths are derived from one XDG path adapter.
- **Encrypted cache**: vault snapshots and outbox data are encrypted on disk with a key derived from the master password using Argon2id and a persisted per-cache salt.
- **Secret Service storage**: Bitwarden token bundles, PIN verifier profiles, and quick-unlock envelopes are stored in the Linux Secret Service keyring.
- **Local PIN model**: the local PIN is verified with Argon2id and is never sent to Bitwarden. The quick-unlock envelope is bound to the current boot/session.
- **No plaintext search index**: the search index is rebuilt in memory and dropped on relock.
- **Restrictive file permissions**: config/cache directories use `0700`; config/cache files use `0600`.
- **No HTTP body dumps**: `make safety` checks for accidental request/response dumps and unsafe persistence patterns.
- **No secret logging**: passwords, tokens, PINs, vault keys, and vault content must never be written to logs.

## Offline-First Sync / Outbox / Conflicts

Mutations are attempted against the remote server first. If the server is unreachable, the mutation is queued in an encrypted local outbox and replayed on the next successful sync.

If a local mutation conflicts with a remote change for the same item, the service records a conflict and marks the item. Conflict resolution primitives exist in the service layer; the full GUI conflict-resolution flow is still planned.

The `sync` CLI command is currently informational; background sync runs after unlock/login when enabled. Full-unlock sessions use the resident sync path, while PIN-unlock sessions use a cache-only sync path that refreshes encrypted cache/outbox state without leaving the full vault resident in service memory. Sync ticks that fire while the omnibox is in form/edit mode are skipped until the next interval.

## Testing

```sh
# All tests
go test ./...

# Headless tests excluding GTK-dependent code
go test -tags nogtk ./...

# Race detection
go test -race -tags nogtk ./...

# Safety checks
make safety

# Full check suite
make check
```

No tests run against a live Bitwarden server by default. Tests use in-memory or local isolated data.

## Dependency Policy

Dependencies are pinned in `go.mod` and `go.sum`. Public releases must not require local `replace` directives. No vendored dependency tree is committed.

`github.com/bnema/puregotk` transitively uses `github.com/bnema/purego`, a maintained fork of the cgo-free FFI library needed for the current GTK/layer-shell runtime path. If those patches are merged upstream, the dependency can move back to the upstream module.

## Known Limitations

- Attachments are not supported yet.
- Clipboard integration uses the GTK/GDK clipboard backend.
- `open_url` is accepted by config validation but not implemented in the GUI.
- Conflict resolution service methods exist, but GUI conflict resolution is incomplete.
- Editing existing items is supported, but adding custom fields in the form is not yet available.

## License

MIT — see [LICENSE](LICENSE).
