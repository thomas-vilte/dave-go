package codecs

import "github.com/thomas-vilte/dave-go/frame"

// vp8Ranges determina los rangos unencrypted para frames VP8.
//
// Según RFC 7741 sección 4.3, el header VP8 tiene un flag de key frame (bit P):
//
//		 0 1 2 3 4 5 6 7
//		+-+-+-+-+-+-+-+-+
//		|Size0|H| VER |P|
//		+-+-+-+-+-+-+-+-+
//
//	  - Si P=0 (key frame): dejar 10 bytes sin cifrar para cubrir el header VP8
//	    completo sin comprimir (incluye picture ID, spatial/temporal info, etc.)
//	  - Si P=1 (non-key frame): dejar solo 1 byte sin cifrar (el payload header)
//
// Referencia: protocol.md "VP8":
// "VP8 frames leave 1 or 10 bytes unencrypted, depending on whether or not
// the incoming frame is a key frame"
// "If P = 0, leave 10 bytes unencrypted to cover the full uncompressed VP8 header"
// "Else P = 1, leave 1 byte unencrypted (just the payload header)"
func vp8Ranges(payload []byte) ([]frame.Range, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	// El bit P (inverse key frame flag) es el bit menos significativo del primer byte.
	// P=0 significa key frame, P=1 significa non-key frame.
	p := payload[0]
	isKeyFrame := (p & 0x01) == 0

	if isKeyFrame {
		// Key frame: dejar 10 bytes sin cifrar
		if len(payload) >= 10 {
			return []frame.Range{{Offset: 0, Length: 10}}, nil
		}
		// Frame más corto que 10 bytes: dejar todo sin cifrar
		return []frame.Range{{Offset: 0, Length: len(payload)}}, nil
	}

	// Non-key frame: dejar 1 byte sin cifrar (solo el payload header)
	return []frame.Range{{Offset: 0, Length: 1}}, nil
}
