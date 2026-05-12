# Changelog

All notable changes to `gtk4-layershell-bitwarden` are documented here.

## v0.1.0 - 2026-05-12

Initial public release.

### Added

- GTK4 layer-shell overlay for Wayland compositors.
- Bitwarden login with US, EU, and self-hosted server selection.
- Linux Secret Service storage for token bundles, PIN profiles, and quick-unlock envelopes.
- Local PIN quick unlock with boot/session-bound envelope material.
- Encrypted vault cache and encrypted outbox storage using XDG paths.
- Vault search, detail view, item creation, editing, trash/restore/delete flows.
- Password generator UI.
- Background sync, offline outbox replay, and service-layer conflict detection.
- File-only rotating logs with no-secret logging policy.

### Known limitations

- Attachments are not supported yet.
- Clipboard integration is not wired into every GTK primary-action path.
- `open_url` is accepted by config validation but not implemented in the GUI.
- GUI conflict resolution is incomplete.
- Adding custom fields in the item form is not yet available.
