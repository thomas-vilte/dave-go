package mediakeys

import (
	"fmt"
	"strings"
)

// DisplayableCode implements the algorithm defined in protocol.md "Displayable
// Codes" — a flexible variation of Signal's displayable code algorithm.
//
// For a given input byte array, desired code length (in digits) and group size:
//
//   - len(secret) must be >= codeLen / groupSize * groupSize (enough bytes to
//     cover all groups; the spec phrases it as "input data length is equal to
//     or greater than the desired code length").
//   - codeLen must be a multiple of groupSize.
//   - groupSize must be < 8 (so 10^groupSize fits in a uint64).
//
// The loop reads `groupSize` bytes at a time, big-endian MSB→LSB, modulo
// 10^groupSize, and pads each group with leading zeros to width groupSize.
// The result is a digit string of length codeLen with no separators —
// integrators format ( dashes, spaces ) for display as they see fit.
//
// Reference vectors used by Discord first-party clients:
//
//	epoch authenticator (32 bytes)   -> DisplayableCode(secret, 30, 5) -> 30 digits
//	pairwise fingerprint (64 bytes)  -> DisplayableCode(secret, 45, 5) -> 45 digits
//
// Spec: protocol.md "Displayable Codes".
func DisplayableCode(secret []byte, codeLen, groupSize int) (string, error) {
	if groupSize >= 8 {
		return "", ErrDisplayableGroupSizeTooLarge
	}
	if groupSize <= 0 {
		return "", ErrDisplayableGroupSizeInvalid
	}
	if codeLen <= 0 || codeLen%groupSize != 0 {
		return "", ErrDisplayableCodeLenInvalid
	}
	groups := codeLen / groupSize
	if len(secret) < groups*groupSize {
		return "", ErrDisplayableCodeInputTooShort
	}

	var mod uint64 = 1
	for range groupSize {
		mod *= 10
	}

	var b strings.Builder
	b.Grow(codeLen)
	for i := range groups {
		var n uint64
		off := i * groupSize
		for j := range groupSize {
			n = (n << 8) | uint64(secret[off+j])
		}
		n %= mod
		fmt.Fprintf(&b, "%0*d", groupSize, n)
	}

	return b.String(), nil
}
