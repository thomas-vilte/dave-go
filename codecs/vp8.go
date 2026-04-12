package codecs

import "github.com/thomas-vilte/dave-go/frame"

// vp8Ranges determines the unencrypted ranges for VP8 frames.
//
// Per RFC 7741 section 4.3, the VP8 header has a key frame flag (bit P):
//
//		 0 1 2 3 4 5 6 7
//		+-+-+-+-+-+-+-+-+
//		|Size0|H| VER |P|
//		+-+-+-+-+-+-+-+-+
//
//	  - If P=0 (key frame): leave 10 bytes unencrypted to cover the full
//	    uncompressed VP8 header (includes picture ID, spatial/temporal info, etc.)
//	  - If P=1 (non-key frame): leave just 1 byte unencrypted (the payload header)
//
// Reference: protocol.md "VP8":
// "VP8 frames leave 1 or 10 bytes unencrypted, depending on whether or not
// the incoming frame is a key frame"
// "If P = 0, leave 10 bytes unencrypted to cover the full uncompressed VP8 header"
// "Else P = 1, leave 1 byte unencrypted (just the payload header)"
func vp8Ranges(payload []byte) ([]frame.Range, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	// The P bit (inverse key frame flag) is the least significant bit of the first byte.
	// P=0 means key frame, P=1 means non-key frame.
	p := payload[0]
	isKeyFrame := (p & 0x01) == 0

	if isKeyFrame {
		// Key frame: leave 10 bytes unencrypted
		if len(payload) >= 10 {
			return []frame.Range{{Offset: 0, Length: 10}}, nil
		}
		// Frame shorter than 10 bytes: leave everything unencrypted
		return []frame.Range{{Offset: 0, Length: len(payload)}}, nil
	}

	// Non-key frame: leave 1 byte unencrypted (just the payload header)
	return []frame.Range{{Offset: 0, Length: 1}}, nil
}
