package codecs

import (
	"github.com/thomas-vilte/dave-go/frame"
)

// AV1 OBU types that get dropped during frame transformation.
// The WebRTC packetizer drops these OBUs, so the encryptor needs to remove them
// too, otherwise the depacketizer would see a different frame.
//
// Reference: protocol.md "AV1":
// "The header and payload for OBU types that would be dropped by the WebRTC
// packetizer are dropped by the encrypting frame transformer"
const (
	obuTemporalDelimiter = 2
	obuTileList          = 8
	obuPadding           = 15
)

// prepareAV1Frame transforms the AV1 frame before encryption and computes the
// unencrypted ranges of the resulting frame.
//
// Transformations applied:
//  1. Drops OBUs of type Temporal Delimiter (2), Tile List (8), and Padding (15)
//  2. For the last OBU of the transformed frame: clears the obu_has_size_field bit
//     (bit 1 of the header) and removes the LEB128 size bytes
//
// Removing the size from the last OBU is needed because DAVE supplemental data
// gets appended at the end of the encrypted frame. If the last OBU had a size
// field, the WebRTC depacketizer would interpret the supplemental data as part
// of the OBU.
//
// The returned ranges correspond to the transformed frame and cover each OBU's
// header (1 byte) + optional extension (1 byte) + LEB128 size (for OBUs that
// aren't the last). Each OBU's payload is fully encrypted.
//
// Reference: protocol.md "AV1"
func prepareAV1Frame(payload []byte) ([]byte, []frame.Range, error) {
	if len(payload) == 0 {
		return nil, nil, nil
	}

	type parsedOBU struct {
		headerByte byte
		hasExt     bool
		extByte    byte
		sizeBytes  []byte // LEB128 size bytes (empty if obu_has_size_field=0)
		data       []byte // OBU payload
	}

	// First pass: parse OBUs and drop the ones we shouldn't keep.
	var obus []parsedOBU
	offset := 0

	for offset < len(payload) {
		headerByte := payload[offset]
		obuType := (headerByte >> 3) & 0x0F
		hasExt := (headerByte>>2)&0x01 == 1
		hasSize := (headerByte>>1)&0x01 == 1
		offset++

		var extByte byte
		if hasExt {
			if offset >= len(payload) {
				break
			}
			extByte = payload[offset]
			offset++
		}

		var sizeField []byte
		var payloadSize int
		if hasSize {
			size, n, err := decodeLEB128(payload[offset:])
			if err != nil {
				return nil, nil, err
			}
			sizeField = make([]byte, n)
			copy(sizeField, payload[offset:offset+n])
			payloadSize = int(size)
			offset += n
		} else {
			// No size field: the OBU takes up the rest of the frame
			payloadSize = len(payload) - offset
		}

		if offset+payloadSize > len(payload) {
			payloadSize = len(payload) - offset
		}

		if shouldDropOBU(obuType) {
			offset += payloadSize
			continue
		}

		obuData := make([]byte, payloadSize)
		copy(obuData, payload[offset:offset+payloadSize])
		obus = append(obus, parsedOBU{
			headerByte: headerByte,
			hasExt:     hasExt,
			extByte:    extByte,
			sizeBytes:  sizeField,
			data:       obuData,
		})
		offset += payloadSize
	}

	if len(obus) == 0 {
		return nil, nil, nil
	}

	// Second pass: build the transformed frame and compute ranges.
	var transformed []byte
	var ranges []frame.Range
	writeOffset := 0

	for i, obu := range obus {
		isLast := i == len(obus)-1
		unencryptedStart := writeOffset

		// Header byte: for the last OBU, clear obu_has_size_field (bit 1)
		h := obu.headerByte
		if isLast {
			h &^= 0x02
		}
		transformed = append(transformed, h)
		writeOffset++

		// Extension byte opcional
		if obu.hasExt {
			transformed = append(transformed, obu.extByte)
			writeOffset++
		}

		// LEB128 size: include in all OBUs except the last one.
		// The last OBU already has obu_has_size_field=0, so no size bytes needed.
		if !isLast && len(obu.sizeBytes) > 0 {
			transformed = append(transformed, obu.sizeBytes...)
			writeOffset += len(obu.sizeBytes)
		}

		// The header (+ ext + size if not last) stays unencrypted
		unencryptedLen := writeOffset - unencryptedStart
		if unencryptedLen > 0 {
			ranges = append(ranges, frame.Range{
				Offset: unencryptedStart,
				Length: unencryptedLen,
			})
		}

		// OBU payload: gets fully encrypted
		transformed = append(transformed, obu.data...)
		writeOffset += len(obu.data)
	}

	return transformed, ranges, nil
}

// shouldDropOBU returns whether an OBU type should be dropped entirely
// during frame transformation.
func shouldDropOBU(obuType byte) bool {
	return obuType == obuTemporalDelimiter ||
		obuType == obuTileList ||
		obuType == obuPadding
}

// decodeLEB128 decodes an unsigned LEB128 integer (up to 8 bytes).
// Returns the value, number of bytes consumed, and any error.
func decodeLEB128(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, frame.ErrInvalidULEB128
	}
	var value uint64
	var shift uint
	for i := 0; i < len(data) && i < 8; i++ {
		b := data[i]
		value |= uint64(b&0x7F) << shift
		if b < 0x80 {
			return value, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, frame.ErrInvalidULEB128
}
