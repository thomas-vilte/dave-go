// Package session implementa la sesión DAVE drop-in replacement de godave.Session.
//
// Es el punto de integración entre disgo-fork/voice y las capas criptográficas DAVE:
//
//	disgo-fork/voice
//	  └── godave.Session (interfaz)
//	        └── dave/session (implementación)
//	              ├── dave/mediakeys  → derivación de sender keys por epoch
//	              ├── dave/codecs     → cifrado codec-aware (OPUS, VP8, H26x, AV1)
//	              └── dave/frame      → formato de frame DAVE encrypt/decrypt
//
// Máquina de estados DAVE:
//
//	idle ──[OnSelectProtocolAck]──► protocol_ready
//	  │
//	  ├──[OnDavePrepareEpoch(epoch=1)]──► new_group
//	  │       └── enviar KeyPackage
//	  │
//	  ├──[OnDavePrepareTransition]──► prepare_transition
//	  │       └── procesar commit/welcome → pendingEpoch
//	  │
//	  └──[OnDaveExecuteTransition]──► active
//	          └── swap pendingEpoch → activeEpoch
//
// Data path (envío):
//
//	frame OPUS → codecs.Encrypt(OPUS, frame, key, nonce) → frame DAVE
//	  donde: key = ratchet.GetKey(generation), nonce = sendCounter.Next()
//
// Data path (recepción):
//
//	frame DAVE → frame.Decrypt → OPUS plaintext
//	  donde: key = activeEpoch.senders[userID].ratchet.GetKey(generation)
//
// Referencias:
//   - protocol.md "Sender Key Derivation"
//   - protocol.md "Key Rotation"
//   - protocol.md "Encoded Frame Transforms"
//   - godave.Session interface (github.com/disgoorg/godave)
package session
