# dave-go

This is a pure Go DAVE implementation that targets the `github.com/disgoorg/godave.Session` interface.

I originally started this while trying to get the MLS parts needed for DAVE working in pure Go, and it ended up growing from there.

It is built on top of `github.com/thomas-vilte/mls-go`.

## Status

It works, but there are still a few rough edges and things I want to clean up.

## What is here

- `codecs`: codec-aware frame transforms
- `frame`: DAVE frame encrypt/decrypt logic
- `mediakeys`: sender key derivation and ratchets
- `session`: `godave.Session` implementation

## Example

There is a small `disgo` voice example in `examples/voice` using:

```go
voice.WithDaveSessionCreateFunc(session.New)
```

## Notes

- the example streams Opus frames from a local `.dca` file
- package documentation is now in English, but some internal comments may still be cleaned up over time
