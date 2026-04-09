// Package mediakeys implementa la derivación de media keys de DAVE a partir del
// MLS exporter secret del epoch actual.
//
// DAVE define un ratchet por sender y por epoch:
//
//	sender_base_secret = MLS-Exporter("Discord Secure Frames v0", littleEndianSenderID, 16)
//	sender_ratchet     = KeyRatchet(sender_base_secret)
//	sender_key[g]      = sender_ratchet.GetKey(g)
//
// Donde `g` es la generation extraída del byte más significativo del truncated
// synchronization nonce. Cuando el epoch cambia, el exporter_secret cambia y por
// lo tanto cambia también el sender_base_secret de todos los senders.
//
// Referencias:
//   - protocol.md "Sender Key Derivation"
//   - protocol.md "Key Rotation"
//   - RFC 9420 §8.5 MLS-Exporter
//   - RFC 9420 §9.1 sender ratchet para AEAD
package mediakeys
