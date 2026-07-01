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
//	The session is single-use per voice connection. The integrator MUST
//	call Closer.Close() when the session is discarded (channel move, voice
//	disconnect) so the internal recovery/commit watchdogs exit promptly.
//	Without it, an old session can keep re-arming invalidations on a
//	channel the bot no longer occupies.
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
//   - godave.Session.Ready() returns the boolean snapshot. This is the form
//     the audio layer is expected to call on every frame.
//   - Reporter.State().Ready is the same boolean exposed via the Reporter
//     interface; the Reporter is obtained as the first argument of the
//     closure passed to session.NewWithReporter. State() additionally
//     exposes the active EpochID and the start of any degraded window
//     (DegradedSince), which audio senders can use to decide whether to
//     stop feeding frames.
//   - Reporter.WaitReady(ctx) blocks until the first E2EE epoch activates
//     and returns the time the call took. Use it right after creating the
//     session to measure first-handshake latency or to gate startup that
//     must wait for encryption.
//
// Plain passthrough (e.g. on a protocol-version-0 channel) returns !Ready
// forever; the integrator should distinguish that stable state from a
// transient handshake window by reading State().ProtocolVersion: 0 means
// "no E2EE on this channel", >0 plus !Ready means "handshake pending". An
// audio sender that doesn't want to block indefinitely can gate on
// (State().Ready || State().ProtocolVersion == 0).
// References:
//   - protocol.md "Sender Key Derivation"
//   - protocol.md "Key Rotation"
//   - protocol.md "Encoded Frame Transforms"
//   - godave.Session interface (github.com/disgoorg/godave)
package session
