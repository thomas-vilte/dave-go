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
//	  └──[OnDaveExecuteTransition]──► active
//	          └── swap pendingEpoch -> activeEpoch
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
// References:
//   - protocol.md "Sender Key Derivation"
//   - protocol.md "Key Rotation"
//   - protocol.md "Encoded Frame Transforms"
//   - godave.Session interface (github.com/disgoorg/godave)
package session
