// Package mediakeys implements DAVE media key derivation from the current MLS
// epoch exporter secret.
//
// DAVE defines a per-sender, per-epoch ratchet:
//
//	sender_base_secret = MLS-Exporter("Discord Secure Frames v0", littleEndianSenderID, 16)
//	sender_ratchet     = KeyRatchet(sender_base_secret)
//	sender_key[g]      = sender_ratchet.GetKey(g)
//
// Here `g` is the generation extracted from the most significant byte of the
// truncated synchronization nonce. When the epoch changes, the exporter secret
// changes too, so every sender gets a new sender_base_secret.
//
// References:
//   - protocol.md "Sender Key Derivation"
//   - protocol.md "Key Rotation"
//   - RFC 9420 §8.5 MLS-Exporter
//   - RFC 9420 §9.1 sender ratchet for AEAD
package mediakeys
