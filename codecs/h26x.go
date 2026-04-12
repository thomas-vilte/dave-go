package codecs

import (
	"bytes"

	"github.com/thomas-vilte/dave-go/frame"
)

// maxH26xRetries is the max number of nonce retries to avoid start code
// sequence collisions in H264/H265 ciphertext.
const maxH26xRetries = 10

// encryptH26x encrypts an H264 or H265 frame with nonce retry logic.
//
// After each encryption attempt, it scans the ciphertext and footer for
// start code sequences (0x000001 or 0x00000001). If a collision is detected,
// it increments the nonce and retries up to maxH26xRetries times.
//
// Unencrypted bytes (non-VCL NAL units) are excluded from the scan because
// they legitimately contain start codes by design.
//
// Reference: protocol.md "H264 & H265":
// "If a start code sequence is encountered the nonce is incremented and
// encryption is re-attempted"
func encryptH26x(kind Kind, plaintext, key []byte, baseNonce uint32) ([]byte, error) {
	ranges, err := h26xRanges(kind, plaintext)
	if err != nil {
		return nil, err
	}

	var lastResult []byte
	for attempt := 0; attempt < maxH26xRetries; attempt++ {
		nonce := nonceForEncryption(baseNonce, attempt)
		encrypted, err := frame.Encrypt(frame.EncryptParams{
			Plaintext:         plaintext,
			Key:               key,
			TruncatedNonce:    nonce,
			UnencryptedRanges: ranges,
		})
		if err != nil {
			return nil, err
		}

		// Extract only the ciphertext bytes (exclude unencrypted ranges)
		// to check for collisions. Non-VCL NAL units have start codes
		// by design and shouldn't be included in the check.
		interleavedFrame := encrypted[:len(plaintext)]
		ciphertextBytes := frame.ExtractCiphertext(interleavedFrame, ranges)
		footer := encrypted[len(plaintext):]

		if !hasStartCodeSequence(ciphertextBytes) && !hasStartCodeSequence(footer) {
			return encrypted, nil
		}
		lastResult = encrypted
	}

	// If we ran out of retries, return the last result we have.
	return lastResult, nil
}

// h26xRanges determines the unencrypted ranges for H264 and H265 frames.
//
// Process:
//  1. Iterates through NAL units looking for start codes (0x000001 or 0x00000001)
//  2. Classifies each NAL unit as VCL (video coding layer) or non-VCL
//  3. VCL NAL units are fully encrypted (they contain video data)
//  4. Non-VCL NAL units stay unencrypted (metadata read by packetizer/depacketizer)
//
// Additional note: after encryption, the ciphertext and supplemental data must be
// scanned to make sure no start code sequence (0x000001 or 0x00000001) appears.
// If one does, the nonce is incremented and encryption is retried (up to 10 times).
// This prevents the packetizer/depacketizer from mistaking ciphertext for NAL units.
//
// Reference: protocol.md "H264 & H265":
// "Fully encrypt the payload of any Video Coding Layer (VCL) NAL unit"
// "Leave unencrypted portions of non-VCL NAL units that are read by the
// packetizer/depacketizer"
func h26xRanges(kind Kind, payload []byte) ([]frame.Range, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	var ranges []frame.Range
	offset := 0

	for offset < len(payload) {
		// Look for start code: 3 bytes (0x000001) or 4 bytes (0x00000001)
		startCodeLen := 0
		if offset+3 <= len(payload) && payload[offset] == 0 && payload[offset+1] == 0 && payload[offset+2] == 1 {
			startCodeLen = 3
		} else if offset+4 <= len(payload) && payload[offset] == 0 && payload[offset+1] == 0 && payload[offset+2] == 0 && payload[offset+3] == 1 {
			startCodeLen = 4
		}

		if startCodeLen == 0 {
			break
		}

		nalStart := offset + startCodeLen
		if nalStart >= len(payload) {
			break
		}

		// Figure out NAL unit type
		nalHeader := payload[nalStart]
		var nalType byte
		if kind == CodecH264 {
			// H264: lowest 5 bits of the first byte
			nalType = nalHeader & 0x1F
		} else {
			// H265: bits 1-6 of the first byte (shift 1, mask 0x3F)
			nalType = (nalHeader >> 1) & 0x3F
		}

		// VCL NAL units contain video data and get fully encrypted
		// H264: types 1-5 are VCL
		// H265: types 0-31 are VCL (BLA, CRA, IDR, etc.)
		isVCL := false
		if kind == CodecH264 {
			isVCL = nalType >= 1 && nalType <= 5
		} else {
			isVCL = nalType <= 31
		}

		// Find the start of the next NAL unit
		nextOffset := findNextStartCode(payload, nalStart)
		if nextOffset == -1 {
			nextOffset = len(payload)
		}

		// Non-VCL NAL units stay unencrypted
		if !isVCL {
			nalLength := nextOffset - offset
			ranges = append(ranges, frame.Range{
				Offset: offset,
				Length: nalLength,
			})
		}

		offset = nextOffset
	}

	return ranges, nil
}

// findNextStartCode looks for the next H26x start code starting from `from`.
// Returns -1 if none is found.
func findNextStartCode(payload []byte, from int) int {
	for i := from; i < len(payload)-3; i++ {
		if payload[i] == 0 && payload[i+1] == 0 && (payload[i+2] == 1 || (payload[i+2] == 0 && payload[i+3] == 1)) {
			return i
		}
	}
	return -1
}

// hasStartCodeSequence checks whether the data contains an H26x start code sequence.
// Used during encryption to detect collisions and retry with a different nonce.
//
// Reference: protocol.md "H264 & H265":
// "If a start code sequence is encountered the nonce is incremented and
// encryption is re-attempted"
func hasStartCodeSequence(data []byte) bool {
	return bytes.Contains(data, []byte{0x00, 0x00, 0x01}) ||
		bytes.Contains(data, []byte{0x00, 0x00, 0x00, 0x01})
}

// nonceForEncryption computes the nonce for an encryption attempt.
// In H26x, if encryption produces start codes in the ciphertext, the nonce is
// incremented and retried (up to 10 times).
func nonceForEncryption(baseNonce uint32, attempt int) uint32 {
	return baseNonce + uint32(attempt)
}
