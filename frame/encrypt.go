package frame

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// EncryptWithCipherParams holds the parameters for EncryptWithCipher.
// Same as EncryptParams but accepts a pre-created cipher instead of a raw key.
type EncryptWithCipherParams struct {
	Plaintext         []byte
	Cipher            cipher.AEAD
	TruncatedNonce    uint32
	UnencryptedRanges []Range
}

// EncryptWithCipher encrypts a DAVE frame using a pre-created cipher.
// Allows caching the AES-GCM cipher to avoid recreating it on every frame (hot path).
// Identical to Encrypt() but skips cipher creation.
func EncryptWithCipher(params EncryptWithCipherParams) ([]byte, error) {
	if params.Cipher == nil {
		return nil, fmt.Errorf("cipher nil: %w", ErrInvalidKeyLength)
	}
	if err := ValidateRanges(params.UnencryptedRanges, len(params.Plaintext)); err != nil {
		return nil, err
	}

	return encryptCoreAppend(nil, params.Cipher, params.Plaintext, params.TruncatedNonce, params.UnencryptedRanges)
}

// EncryptWithCipherInto is like EncryptWithCipher but writes the encrypted
// frame into dst and returns the number of bytes written, instead of
// allocating a new slice.
//
// When params.UnencryptedRanges is empty (e.g. OPUS) and
// cap(dst) >= len(params.Plaintext)+16, the AES-GCM seal writes directly into
// dst's backing array and this call performs zero heap allocations. dst and
// params.Plaintext must not overlap.
func EncryptWithCipherInto(dst []byte, params EncryptWithCipherParams) (int, error) {
	if params.Cipher == nil {
		return 0, fmt.Errorf("cipher nil: %w", ErrInvalidKeyLength)
	}
	if err := ValidateRanges(params.UnencryptedRanges, len(params.Plaintext)); err != nil {
		return 0, err
	}

	return encryptInto(dst, params.Cipher, params.Plaintext, params.TruncatedNonce, params.UnencryptedRanges)
}

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
// Reference: protocol.md "Payload Format", "Interleaved protocol media frame".
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

	return encryptCoreAppend(nil, gcm, params.Plaintext, params.TruncatedNonce, params.UnencryptedRanges)
}

// EncryptInto is like Encrypt but writes the encrypted frame into dst and
// returns the number of bytes written, instead of allocating a new slice.
//
// When params.UnencryptedRanges is empty (e.g. OPUS) and
// cap(dst) >= len(params.Plaintext)+16, the AES-GCM seal writes directly into
// dst's backing array and this call performs zero heap allocations. dst and
// params.Plaintext must not overlap.
func EncryptInto(dst []byte, params EncryptParams) (int, error) {
	if len(params.Key) != 16 {
		return 0, ErrInvalidKeyLength
	}
	if err := ValidateRanges(params.UnencryptedRanges, len(params.Plaintext)); err != nil {
		return 0, err
	}

	gcm, err := newGCM8(params.Key)
	if err != nil {
		return 0, err
	}

	return encryptInto(dst, gcm, params.Plaintext, params.TruncatedNonce, params.UnencryptedRanges)
}

// encryptInto fills dst[:0] via encryptCoreAppend and copies the result back
// into dst, returning the number of bytes written. If dst has enough spare
// capacity, encryptCoreAppend writes directly into dst's backing array and
// the final copy is a self-copy (no allocation, no data movement).
func encryptInto(dst []byte, gcm cipher.AEAD, plaintext []byte, truncatedNonce uint32, unencryptedRanges []Range) (int, error) {
	out, err := encryptCoreAppend(dst[:0], gcm, plaintext, truncatedNonce, unencryptedRanges)
	if err != nil {
		return 0, err
	}
	if len(out) > cap(dst) {
		return 0, fmt.Errorf("%w: need %d, have %d", ErrBufferTooSmall, len(out), cap(dst))
	}

	return copy(dst[:len(out)], out), nil
}

// encryptCoreAppend appends an encrypted DAVE frame to dst and returns the
// extended slice. dst is typically dst[:0] of a caller-owned buffer (see
// encryptInto) or nil to always allocate.
//
// For the no-ranges case (OPUS, VP9), gcm.Seal writes ciphertext+tag directly
// into dst's spare capacity, and the ULEB128-encoded nonce is built on the
// stack, so this performs a single small allocation (the 12-byte nonce array,
// which escapes because gcm.Seal is an interface method call) as long as
// cap(dst) >= len(plaintext)+16 — down from the ~3 allocations and 2 copies
// of the original implementation.
func encryptCoreAppend(dst []byte, gcm cipher.AEAD, plaintext []byte, truncatedNonce uint32, unencryptedRanges []Range) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint32(nonce[8:], truncatedNonce)

	var nonceBuf [5]byte
	nonceBytes := appendULEB128(nonceBuf[:0], truncatedNonce)

	if len(unencryptedRanges) == 0 {
		// gcm8.Seal returns dst extended by ciphertext+tag(8).
		out := gcm.Seal(dst, nonce[:], plaintext, nil)

		supplSize := uint8(8 + len(nonceBytes) + 1 + 2)
		out = append(out, nonceBytes...)
		out = append(out, supplSize)
		out = append(out, 0xFA, 0xFA)

		return out, nil
	}

	ciphertext := ExtractCiphertext(plaintext, unencryptedRanges)

	// AAD = concatenation of unencrypted bytes in order.
	// Reference: protocol.md "Interleaved protocol media frame"
	aad := buildAAD(plaintext, unencryptedRanges)

	// Encrypt with AES-128-GCM (tag truncated to 8 bytes).
	sealed := gcm.Seal(nil, nonce[:], ciphertext, aad)
	ciphertextOut := sealed[:len(sealed)-8]
	tag := sealed[len(sealed)-8:]

	out := appendInterleaved(dst, plaintext, unencryptedRanges, ciphertextOut)
	out = append(out, tag...)
	out = append(out, nonceBytes...)

	rangesStart := len(out)
	for _, r := range unencryptedRanges {
		out = appendULEB128(out, uint32(r.Offset))
		out = appendULEB128(out, uint32(r.Length))
	}
	rangesLen := len(out) - rangesStart

	// Suppl. Size covers all the supplemental content:
	// tag(8) + nonce(ULEB128) + rangesData + this byte(1) + magic(2)
	// Reference: protocol.md "Protocol supplemental data size"
	supplSize := uint8(8 + len(nonceBytes) + rangesLen + 1 + 2)
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
// Reference: protocol.md "Payload Format", "Protocol Frame Check".
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

	// Reconstruct the sealed message: ciphertext + tag. Build a fresh slice so we
	// never append into ciphertext's backing array (which aliases the input frame).
	sealed := make([]byte, 0, len(ciphertext)+len(parsed.Tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, parsed.Tag...)
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
// Reference: protocol.md "Protocol Frame Check".
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
func buildAAD(frame []byte, ranges []Range) []byte {
	aad := make([]byte, 0, len(frame))
	for _, r := range ranges {
		aad = append(aad, frame[r.Offset:r.Offset+r.Length]...)
	}

	return aad
}

// appendInterleaved appends the interleaved frame to dst: a copy of the
// original frame with the encrypted positions (outside unencrypted ranges)
// replaced by the corresponding ciphertext.
func appendInterleaved(dst []byte, original []byte, ranges []Range, ciphertext []byte) []byte {
	start := len(dst)
	dst = append(dst, original...)
	out := dst[start:]

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

	return dst
}

// Parse analyzes a complete DAVE frame and extracts its footer components.
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

	footerStart := len(packet) - supplSize
	if footerStart < 0 {
		return nil, fmt.Errorf("invalid footer position: %w", ErrInvalidSupplementalSize)
	}

	footer := packet[footerStart : len(packet)-3]
	expectedFooterLen := supplSize - 3
	if len(footer) != expectedFooterLen {
		return nil, fmt.Errorf("footer length mismatch: %w", ErrInvalidSupplementalSize)
	}

	pos := 0

	tag := footer[pos : pos+8]
	pos += 8

	nonce, n, err := DecodeULEB128(footer[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

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
