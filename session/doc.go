// Package session implements a DAVE session as a drop-in replacement for
// godave.Session.
//
// It is the integration point between the voice layer and the DAVE crypto
// packages:
//
//	voice
//	  └── godave.Session (interface)
//	        └── dave-go/session (implementation)
//	              ├── dave-go/mediakeys  -> per-epoch sender key derivation
//	              ├── dave-go/codecs     -> codec-aware encryption (OPUS, VP8, H26x, AV1)
//	              └── dave-go/frame      -> DAVE frame encrypt/decrypt format
//
// DAVE state machine:
//
//	idle ──[OnSelectProtocolAck]──► protocol_ready
//	  │
//	  ├──[OnDavePrepareEpoch(epoch=1)]──► new_group
//	  │       └── send KeyPackage
//	  │
//	  ├──[OnDavePrepareTransition]──► prepare_transition
//	  │       └── process commit/welcome -> pendingEpoch
//	  │
//	  ├──[OnDaveExecuteTransition]──► active
//	  │       └── swap pendingEpoch -> activeEpoch
//	  │
//	  └──[Close]──► closed (integrator-initiated; cancels watchdog goroutines)
//
// Lifecycle:
//
//	The session can be reused across channel moves and gateway reconnects:
//	each select_protocol_ack resets it for the new connection, as disgo does
//	with one session per voice Conn. The integrator should call
//	Session.Close() when the session is discarded (voice disconnect) so the
//	internal recovery/commit watchdogs exit promptly.
//	The watchdogs are time-bounded (at most maxRecoveryAttempts retries of
//	recoveryTimeout each, plus the key package back-off while the gateway is
//	down, ~83s worst case), so a missed Close is not a
//	permanent leak — but until they expire the old session can keep re-arming
//	invalidations on a channel the bot no longer occupies. Close satisfies
//	io.Closer, so a voice layer holding only the godave.Session can tear
//	it down via a plain io.Closer type assertion.
//
// Send path:
//
//	frame OPUS → codecs.Encrypt(OPUS, frame, key, nonce) → frame DAVE
//	  where: key = ratchet.GetKey(generation), nonce = sendCounter.Next()
//
// Receive path:
//
//	frame DAVE → frame.Decrypt → OPUS plaintext
//	  where: key = activeEpoch.senders[userID].ratchet.GetKey(generation)
//
// E2EE readiness:
//
// There are three ways to ask about readiness. Which one to use depends on
// whether the caller blocks or polls, and on what it is asking:
//
//   - Session.Ready() reports whether frames can flow: an E2EE epoch is
//     active, or protocol version 0 has been negotiated and none will be.
//     This is the form the audio layer is expected to call on every frame.
//   - Session.State().Ready reports whether frames are end-to-end
//     encrypted, so it stays false on a transport-only channel. State()
//     additionally
//     exposes the active EpochID and the start of any degraded window
//     (DegradedSince), which audio senders can use to decide whether to
//     stop feeding frames.
//   - Session.WaitReady(ctx) blocks until the first E2EE epoch activates
//     and returns the time the call took. Use it right after creating the
//     session to measure first-handshake latency or to gate startup that
//     must wait for encryption.
//
// Plain passthrough (e.g. on a protocol-version-0 channel) leaves
// State().Ready false for ever; Session.ShouldHoldFrames() tells that stable
// state apart from a transient handshake window (it reads
// State().ProtocolVersion under the hood: 0 means "no E2EE on this channel",
// >0 plus !Ready means "handshake pending") — audio senders should gate on it
// instead of combining the two fields by hand.
//
// To get a *Session handle when the voice layer creates sessions internally,
// pass CreateFunc(WithSessionHook(...)) as the voice manager's session
// factory; the hook receives each *Session as it is created.
// References:
//   - protocol.md "Sender Key Derivation"
//   - protocol.md "Key Rotation"
//   - protocol.md "Encoded Frame Transforms"
//   - godave.Session interface (github.com/disgoorg/godave)
package session
