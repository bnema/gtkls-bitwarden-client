# gtk4-layershell-bitwarden

A GTK4 layer-shell Bitwarden client for Linux desktop environments.

## Status

**v0.1.0 — in progress**

This is an early development version. The project is being scaffolded and is not yet functional.

## Prerequisites

- Go 1.26+
- GTK4 development libraries
- Layer Shell protocol support (wlroots-based compositor)

## Local SDK Replacement

During development, the project uses a local copy of the Bitwarden Go SDK:

```
replace github.com/bnema/bitwarden-go-sdk => ../bitwarden-go-sdk
```

This is already configured in `go.mod`.

## Dependencies

External packages are fetched with:

```
go get <module>@latest
```

## Testing

- No live Bitwarden tests run by default.
- Tests are focused on local logic and isolated behavior.

## Goals

- No plaintext vault cache on disk
- No plaintext search index on disk
- No plaintext outbox on disk; queued offline operations will be stored only in encrypted form

## License

MIT
