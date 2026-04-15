# dave-go

[![Release](https://img.shields.io/github/v/release/thomas-vilte/dave-go?sort=semver)](https://github.com/thomas-vilte/dave-go/releases)
[![License](https://img.shields.io/github/license/thomas-vilte/dave-go)](https://github.com/thomas-vilte/dave-go/blob/master/LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/thomas-vilte/dave-go.svg)](https://pkg.go.dev/github.com/thomas-vilte/dave-go)
[![CI](https://github.com/thomas-vilte/dave-go/actions/workflows/go.yml/badge.svg)](https://github.com/thomas-vilte/dave-go/actions/workflows/go.yml)

`dave-go` is a pure Go DAVE implementation targeting the `github.com/disgoorg/godave.Session` interface.

I originally started this while trying to get the MLS pieces needed for DAVE working in pure Go, and it ended up growing into a standalone implementation. It is built on top of [`github.com/thomas-vilte/mls-go`](https://github.com/thomas-vilte/mls-go).

## Status

It is working and already usable, but I still consider it early and there are a few rough edges I want to clean up over time.

## Install

```bash
go get github.com/thomas-vilte/dave-go
```

For a tagged version:

```bash
go get github.com/thomas-vilte/dave-go@v0.1.0
```

## Usage

Use the session implementation anywhere a `godave.SessionCreateFunc` is expected:

```go
import (
	"github.com/disgoorg/disgo/voice"
	"github.com/thomas-vilte/dave-go/session"
)

voice.WithDaveSessionCreateFunc(session.New)
```

There is also a small `disgo` voice example in [`examples/voice`](https://github.com/thomas-vilte/dave-go/tree/master/examples/voice).

## Packages

- [`session`](https://pkg.go.dev/github.com/thomas-vilte/dave-go/session): `godave.Session` implementation
- [`mediakeys`](https://pkg.go.dev/github.com/thomas-vilte/dave-go/mediakeys): sender key derivation and ratchets
- [`frame`](https://pkg.go.dev/github.com/thomas-vilte/dave-go/frame): DAVE frame encrypt/decrypt logic
- `codecs`: codec-aware frame transforms used by the session layer

## References

- [`godave`](https://github.com/disgoorg/godave)
- [`mls-go`](https://github.com/thomas-vilte/mls-go)
- [Go package docs](https://pkg.go.dev/github.com/thomas-vilte/dave-go)
- [`session` package docs](https://pkg.go.dev/github.com/thomas-vilte/dave-go/session)
- [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)

## Notes

- the example streams Opus frames from a local `.dca` file
- some internal comments may still be cleaned up over time
