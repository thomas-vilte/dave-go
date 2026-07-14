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
//	The session is single-use per voice connection. The integrator should
//	call Session.Close() when the session is discarded (channel move, voice
//	disconnect) so the internal recovery/commit watchdogs exit promptly.
//	The watchdogs are time-bounded (at most maxRecoveryAttempts retries of
//	recoveryTimeout each, ~45s worst case), so a missed Close is not a
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
// There are three equivalent ways to ask whether the session can encrypt
// frames end-to-end. Which one to use depends on whether the caller blocks
// or polls:
//
//   - Session.Ready() returns the boolean snapshot. This is the form
//     the audio layer is expected to call on every frame.
//   - Session.State().Ready is the same boolean; State() additionally
//     exposes the active EpochID and the start of any degraded window
//     (DegradedSince), which audio senders can use to decide whether to
//     stop feeding frames.
//   - Session.WaitReady(ctx) blocks until the first E2EE epoch activates
//     and returns the time the call took. Use it right after creating the
//     session to measure first-handshake latency or to gate startup that
//     must wait for encryption.
//
// Plain passthrough (e.g. on a protocol-version-0 channel) returns !Ready
// forever; Session.ShouldHoldFrames() tells that stable state apart from a
// transient handshake window (it reads State().ProtocolVersion under the
// hood: 0 means "no E2EE on this channel", >0 plus !Ready means "handshake
// pending") — audio senders should gate on it instead of combining the two
// fields by hand.
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
