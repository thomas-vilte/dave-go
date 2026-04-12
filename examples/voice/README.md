# voice example

Small `disgo` voice example using `github.com/thomas-vilte/dave-go/session` as the DAVE session implementation.

Environment variables:

- `disgo_token`
- `disgo_guild_id`
- `disgo_channel_id`
- `DCA_FILE` optional, defaults to `nico.dca`

Run it with:

```bash
go run ./examples/voice
```

The example streams Opus frames from a local DCA0 file.

If your file is not named `nico.dca`, set:

```bash
export DCA_FILE=/path/to/file.dca
```
