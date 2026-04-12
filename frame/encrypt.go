package frame

import (
	"encoding/binary"
	"fmt"
)

// Encrypt encrypts a media frame following the DAVE format.
//
// Process:
//  1. Validates the key is 16 bytes (AES-128)
//  2. Validates unencrypted ranges are valid (ordered, non-overlapping, within frame)
//  3. Extracts the bytes to be encrypted (everything NOT in the unencrypted ranges)
//  4. Builds the AAD from the unencrypted bytes (protocol.md: "All of the unencrypted ranges
//     from the frame are joined together and included as additional data")
//  5. Encrypts with AES-128-GCM (tag truncated to 8 bytes) using the nonce expanded to 96 bits
//  6. Builds the interleaved frame: copies the original frame and replaces encrypted zones
//     with ciphertext
//  7. Builds the footer: tag(8) + nonce(ULEB128) + ranges(ULEB128 pairs) + supplSize + 0xFAFA
//
// Reference: protocol.md "Payload Format", "Interleaved protocol media frame"
func Encrypt(params EncryptParams) ([]byte, error) {
	if len(params.Key) != 16 {
		return nil, ErrInvalidKeyLength
	}
	if err := ValidateRanges(params.UnencryptedRanges, len(params.Plaintext)); err != nil {
		return nil, err
	}

	gcm, err := newGCM8(params.Key)
	if err != nil {
		return nil, err
	}

	// Nonce expanded to 96 bits: 8 zero bytes + 4 bytes from the truncated nonce.
	// libdave copies the truncated uint32 byte-by-byte to the end of the nonce (memcpy),
	// which on little-endian platforms produces a little-endian layout.
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint32(nonce[8:], params.TruncatedNonce)

	// Extract ciphertext bytes (everything NOT in unencrypted ranges)
	ciphertext := ExtractCiphertext(params.Plaintext, params.UnencryptedRanges)

	// AAD = concatenation of unencrypted bytes in order
	// Reference: protocol.md "Interleaved protocol media frame":
	// "All of the (potentially discontiguous) unencrypted ranges from the frame are joined
	// together and included as additional data to be authenticated by the AEAD ciphersuite"
	aad := buildAAD(params.Plaintext, params.UnencryptedRanges)

	// Cifrar con AES-128-GCM (tag truncado a 8 bytes)
	sealed := gcm.Seal(nil, nonce, ciphertext, aad)
	ciphertextOut := sealed[:len(sealed)-8]
	tag := sealed[len(sealed)-8:]

	// When there are no unencrypted ranges (e.g. Opus), the whole interleaved frame
	// should be ciphertext. If we use plaintext as the base, buildInterleaved won't
	// replace anything and ends up returning the original unencrypted frame.
	baseFrame := params.Plaintext
	if len(params.UnencryptedRanges) == 0 {
		baseFrame = ciphertextOut
	}

	// Build interleaved frame: original frame with encrypted zones replaced by ciphertext
	out := buildInterleaved(baseFrame, params.UnencryptedRanges, ciphertextOut)

	// Build footer
	out = append(out, tag...)

	nonceBytes := EncodeULEB128(params.TruncatedNonce)
	out = append(out, nonceBytes...)

	var rangesData []byte
	for _, r := range params.UnencryptedRanges {
		rangesData = append(rangesData, EncodeULEB128(uint32(r.Offset))...)
		rangesData = append(rangesData, EncodeULEB128(uint32(r.Length))...)
	}
	out = append(out, rangesData...)

	// Suppl. Size covers all the supplemental content:
	// tag(8) + nonce(ULEB128) + rangesData + this byte(1) + magic(2)
	// Reference: protocol.md "Protocol supplemental data size"
	supplSize := uint8(8 + len(nonceBytes) + len(rangesData) + 1 + 2)
	out = append(out, supplSize)
	out = append(out, 0xFA, 0xFA)

	return out, nil
}

// Decrypt decrypts a DAVE frame and returns the original plaintext along with the nonce.
//
// Process:
//  1. Validates the key is 16 bytes
//  2. Checks that the frame passes the protocol frame check (magic marker 0xFAFA)
//  3. Parses the footer to extract tag, nonce, and unencrypted ranges
//  4. Extracts the ciphertext from the interleaved frame (bytes outside the ranges)
//  5. Builds the AAD from the unencrypted bytes of the interleaved frame
//  6. Decrypts with AES-128-GCM, verifying the authentication tag
//  7. Reconstructs the original plaintext by re-inserting the decrypted bytes into the encrypted positions
//
// Reference: protocol.md "Payload Format", "Protocol Frame Check"
func Decrypt(params DecryptParams) ([]byte, uint32, error) {
	if len(params.Key) != 16 {
		return nil, 0, ErrInvalidKeyLength
	}
	if !LooksLikeDAVEFrame(params.Ciphertext) {
		return nil, 0, ErrFrameTooShort
	}

	parsed, err := Parse(params.Ciphertext)
	if err != nil {
		return nil, 0, err
	}

	gcm, err := newGCM8(params.Key)
	if err != nil {
		return nil, 0, err
	}

	// Expand truncated nonce (32 bits) to full nonce (96 bits)
	// Reference: protocol.md "Truncated synchronization nonce":
	// "The full-size nonce is produced by writing the truncated nonce to the 4 least
	// significant bytes and making the 8 most significant bytes all zero"
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint32(nonce[8:], parsed.TruncatedNonce)

	// Extract ciphertext from interleaved frame (bytes outside unencrypted ranges)
	ciphertext := ExtractCiphertext(parsed.InterleavedFrame, parsed.UnencryptedRanges)

	// AAD = unencrypted bytes from interleaved frame (same ones used in Encrypt)
	aad := buildAAD(parsed.InterleavedFrame, parsed.UnencryptedRanges)

	// Reconstruct the sealed message: ciphertext + tag
	sealed := append(ciphertext, parsed.Tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, 0, err
	}

	// Reconstruct original plaintext: insert decrypted bytes into encrypted positions
	result := ReconstructPlaintext(parsed.InterleavedFrame, plaintext, parsed.UnencryptedRanges)
	return result, parsed.TruncatedNonce, nil
}

// LooksLikeDAVEFrame does a quick check to see if a packet could be a DAVE frame
// by checking the magic marker 0xFAFA at the expected position and the minimum size.
//
// The minimum size of 11 bytes corresponds to:
// tag(8) + min nonce(1) + supplSize(1) + magic(2) = 12 bytes of footer
// but with 0 bytes of interleaved frame, the total minimum is 12.
// We use 11 as a conservative threshold for the quick check.
//
// Reference: protocol.md "Protocol Frame Check"
func LooksLikeDAVEFrame(packet []byte) bool {
	if len(packet) < 11 {
		return false
	}
	if packet[len(packet)-2] != 0xFA || packet[len(packet)-1] != 0xFA {
		return false
	}
	return true
}

// buildAAD builds the Additional Authenticated Data by concatenating the bytes
// from the frame's unencrypted ranges in ascending order.
//
// These bytes are included in the AAD so the SFU can't modify them without
// invalidating the authentication, while keeping them in plaintext so WebRTC
// packetizers/depacketizers can read them.
//
// Reference: protocol.md "Interleaved protocol media frame":
// "All of the (potentially discontiguous) unencrypted ranges from the frame are
// joined together and included as additional data to be authenticated"
func buildAAD(frame []byte, ranges []Range) []byte {
	aad := make([]byte, 0, len(frame))
	for _, r := range ranges {
		aad = append(aad, frame[r.Offset:r.Offset+r.Length]...)
	}
	return aad
}

// buildInterleaved builds the interleaved frame by copying the original frame
// and replacing the encrypted positions (outside unencrypted ranges) with the
// corresponding ciphertext.
//
// Diagram of the process:
//
//	Original:  [UUCCCCUUCCCC]  (U=unencrypted, C=to encrypt)
//	Ciphertext:[cccc]           (just the C bytes concatenated)
//	Result:    [UUccccUUccccc]  (ciphertext inserted back into C positions)
func buildInterleaved(original []byte, ranges []Range, ciphertext []byte) []byte {
	out := make([]byte, len(original))
	copy(out, original)

	cipherPos := 0
	last := 0
	for _, r := range ranges {
		// Copy ciphertext into the gap between the last range and this one
		if r.Offset > last {
			n := r.Offset - last
			copy(out[last:r.Offset], ciphertext[cipherPos:cipherPos+n])
			cipherPos += n
		}
		last = r.Offset + r.Length
	}
	// Copy the rest of the ciphertext after the last range
	if last < len(original) {
		copy(out[last:], ciphertext[cipherPos:])
	}
	return out
}

// Parse analyzes a complete DAVE frame and extracts its footer components.
//
// The footer is located at the end of the packet and contains:
//  1. Truncated authentication tag (8 bytes)
//  2. Truncated synchronization nonce (ULEB128 variable)
//  3. Unencrypted range offset/length pairs (ULEB128 variable)
//  4. Supplemental data size (1 byte)
//  5. Magic marker 0xFAFA (2 bytes)
//
// The supplemental size indicates the size of all content from the tag
// through the magic marker inclusive.
//
// Reference: protocol.md "Payload Format" diagram
func Parse(packet []byte) (*ParsedFrame, error) {
	if len(packet) < 11 {
		return nil, fmt.Errorf("packet too short: %w", ErrFrameTooShort)
	}
	if packet[len(packet)-2] != 0xFA || packet[len(packet)-1] != 0xFA {
		return nil, ErrInvalidMagicMarker
	}

	supplSize := int(packet[len(packet)-3])
	if supplSize < 11 || supplSize > len(packet) {
		return nil, fmt.Errorf("supplemental size %d out of range: %w", supplSize, ErrInvalidSupplementalSize)
	}

	// El frame interleaved ocupa todo el packet menos el supplemental data
	footerStart := len(packet) - supplSize
	if footerStart < 0 {
		return nil, fmt.Errorf("invalid footer position: %w", ErrInvalidSupplementalSize)
	}

	// El footer data es todo menos los 3 bytes finales (supplSize + magic)
	footer := packet[footerStart : len(packet)-3]
	expectedFooterLen := supplSize - 3
	if len(footer) != expectedFooterLen {
		return nil, fmt.Errorf("footer length mismatch: %w", ErrInvalidSupplementalSize)
	}

	pos := 0

	// 1. Truncated authentication tag (8 bytes)
	tag := footer[pos : pos+8]
	pos += 8

	// 2. Truncated synchronization nonce (ULEB128)
	nonce, n, err := DecodeULEB128(footer[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	// 3. Unencrypted range offset/length pairs (ULEB128)
	var ranges []Range
	rangesData := footer[pos:]
	for len(rangesData) > 0 {
		offset, n1, err := DecodeULEB128(rangesData)
		if err != nil {
			break
		}
		rangesData = rangesData[n1:]
		length, n2, err := DecodeULEB128(rangesData)
		if err != nil {
			break
		}
		rangesData = rangesData[n2:]
		ranges = append(ranges, Range{
			Offset: int(offset),
			Length: int(length),
		})
	}

	interleaved := packet[:footerStart]
	if err := ValidateRanges(ranges, len(interleaved)); err != nil {
		return nil, err
	}

	return &ParsedFrame{
		InterleavedFrame:  interleaved,
		Tag:               tag,
		TruncatedNonce:    nonce,
		UnencryptedRanges: ranges,
		SupplementalSize:  uint8(supplSize),
	}, nil
}
