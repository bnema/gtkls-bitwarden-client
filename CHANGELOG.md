# Changelog

All notable changes to `gtkls-bitwarden-client` are documented here.

## v0.2.0 - 2026-05-19

### Added

- Background sync control surface that can suspend sync while editing form data.
- Cache-only background sync persistence for PIN-unlocked sessions.
- Relock-on-quit flow so closing the overlay can avoid leaving a full vault session resident.
- CLI version flag coverage and additional background sync regression tests.

### Changed

- Improved overlay lifecycle behavior around shutdown, sync status, and relock feedback.
- Polished omnibox layout spacing, search input contrast, footer alignment, form margins, and shell shadow styling.
- Constrained edit form width to the omnibox bounds.
- Closed the overlay after successful copy actions.
- Upgraded `bitwarden-go-sdk` to `v0.4.0`.
- Reduced CI release workflow churn and updated `goreleaser/goreleaser-action` to v7.
- Removed early release wording from the README.

### Fixed

- Persisted cache-only conflicts across relock.
- Honored sync suspension and background sync enablement gates.
- Hardened overlay shutdown and lifecycle edge cases.

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
