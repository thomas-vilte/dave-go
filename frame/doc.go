// Package frame implements the DAVE (Discord Audio/Video End-to-End Encryption)
// v1.1 frame format.
//
// The DAVE frame format is defined in protocol.md under "Payload Format". It
// consists of an interleaved media frame, where encrypted and unencrypted
// regions are mixed together, followed by a footer with protocol metadata.
//
// Frame layout:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/                                                               /
//	+            Interleaved protocol media frame (variable)        +
//	/                                                               /
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	+          Truncated 8-byte AES-GCM authentication tag          +
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/       Truncated ULEB128 synchronization nonce (variable)      /
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/    Unencrypted range ULEB128 offset/length pairs (variable)   /
//	+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/               |  Suppl. Size  |      Magic Marker 0xFAFA      |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Footer fields:
//   - Truncated tag: 8 bytes of the AES-128-GCM authentication tag, truncated
//     from the usual 16 bytes to reduce overhead.
//   - Truncated nonce: a 32-bit nonce encoded as ULEB128 and expanded to a
//     96-bit AES-GCM nonce (8 zero bytes + 4 nonce bytes).
//   - Unencrypted ranges: ULEB128 offset/length pairs describing which parts
//     of the interleaved frame stay in plaintext so WebRTC packetizers and
//     depacketizers can still process the frame.
//   - Suppl. Size: 1 byte describing the full size of the supplemental footer
//     data (tag + nonce + ranges + this byte + magic marker).
//   - Magic Marker: 2 bytes `0xFAFA` used for quick DAVE frame detection.
//
// Encryption:
//   - Algorithm: AES-128-GCM with a 64-bit (8 byte) truncated tag.
//   - The truncated tag follows NIST SP 800-38D Appendix C guidance for 64-bit
//     tags.
//   - Unencrypted regions are included as Additional Authenticated Data (AAD)
//     so they keep integrity protection without being encrypted.
//   - Encrypted regions are gathered into a contiguous plaintext block before
//     encryption and then re-inserted back into the original interleaved frame.
//
// References:
//   - protocol.md: "Payload Format", "Truncated authentication tag",
//     "Truncated synchronization nonce", "Unencrypted ranges", "ULEB128 Encoding"
package frame
