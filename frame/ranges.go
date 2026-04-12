package frame

// ValidateRanges checks that the unencrypted ranges are valid:
//   - offsets and lengths are non-negative
//   - they don't exceed the frame size
//   - they are sorted by ascending offset
//   - they don't overlap each other
//
// This validation is critical because invalid ranges could cause
// memory corruption or encryption bypass.
//
// Reference: protocol.md "Protocol Frame Check":
// "Must be ordered by ascending range offset"
// "Must be distinct and not overlapping"
// "Must not overflow the total size of the interleaved media frame"
func ValidateRanges(ranges []Range, size int) error {
	prevEnd := 0
	for i, r := range ranges {
		if r.Offset < 0 || r.Length < 0 {
			return ErrInvalidRanges
		}
		if r.Offset+r.Length > size {
			return ErrInvalidRanges
		}
		if i > 0 && r.Offset < prevEnd {
			return ErrInvalidRanges
		}
		prevEnd = r.Offset + r.Length
	}
	return nil
}

// ContiguousPlaintextSize calculates how many bytes of the frame will be encrypted,
// i.e. the total size minus the bytes in the unencrypted ranges.
func ContiguousPlaintextSize(frameSize int, ranges []Range) int {
	size := frameSize
	for _, r := range ranges {
		size -= r.Length
	}
	return size
}

// ReconstructPlaintext reconstructs the original plaintext from the interleaved
// frame and the decrypted bytes.
//
// The interleaved frame has unencrypted bytes at their original positions and
// ciphertext at the encrypted positions. This function replaces the encrypted
// positions with the decrypted bytes.
//
// Diagram:
//
//	Interleaved: [UUccccUUcccc]  (U=unencrypted original, c=ciphertext)
//	Decrypted:   [CCCC]          (concatenated decrypted bytes)
//	Result:      [UUCCCCUUCCCC]  (reconstructed original plaintext)
func ReconstructPlaintext(interleaved []byte, decrypted []byte, ranges []Range) []byte {
	out := make([]byte, len(interleaved))
	copy(out, interleaved)

	cipherPos := 0
	last := 0
	for _, r := range ranges {
		// Copy decrypted into the gap between the last range and this one
		if r.Offset > last {
			n := r.Offset - last
			copy(out[last:r.Offset], decrypted[cipherPos:cipherPos+n])
			cipherPos += n
		}
		last = r.Offset + r.Length
	}
	// Copy the rest of the decrypted after the last range
	if last < len(interleaved) {
		copy(out[last:], decrypted[cipherPos:])
	}
	return out
}

// ExtractCiphertext extracts the ciphertext bytes from the interleaved frame,
// i.e. all bytes that are NOT in the unencrypted ranges.
//
// Diagram:
//
//	Interleaved: [UUccccUUcccc]  (U=unencrypted, c=ciphertext)
//	Returned:    [cccccccc]      (just the ciphertext bytes concatenated)
func ExtractCiphertext(interleaved []byte, ranges []Range) []byte {
	size := ContiguousPlaintextSize(len(interleaved), ranges)
	out := make([]byte, 0, size)
	last := 0
	for _, r := range ranges {
		if r.Offset > last {
			out = append(out, interleaved[last:r.Offset]...)
		}
		last = r.Offset + r.Length
	}
	if last < len(interleaved) {
		out = append(out, interleaved[last:]...)
	}
	return out
}
