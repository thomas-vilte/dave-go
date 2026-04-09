package codecs

import (
	"github.com/thomas-vilte/dave-go/frame"
)

// Tipos de OBU AV1 que se descartan durante la transformación del frame.
// El packetizer de WebRTC descarta estos OBUs, por lo que el encryptor
// debe eliminarlos para que el depacketizer vea el mismo frame.
//
// Referencia: protocol.md "AV1":
// "The header and payload for OBU types that would be dropped by the WebRTC
// packetizer are dropped by the encrypting frame transformer"
const (
	obuTemporalDelimiter = 2
	obuTileList          = 8
	obuPadding           = 15
)

// prepareAV1Frame transforma el frame AV1 antes del cifrado y calcula los
// rangos unencrypted del frame resultante.
//
// Transformaciones aplicadas:
//  1. Elimina OBUs de tipo Temporal Delimiter (2), Tile List (8) y Padding (15)
//  2. Para el último OBU del frame transformado: limpia el bit obu_has_size_field
//     (bit 1 del header) y elimina los bytes LEB128 del tamaño
//
// La eliminación del tamaño en el último OBU es necesaria porque los datos
// suplementarios DAVE se append al final del frame cifrado. Si el último OBU
// tuviera un campo de tamaño, el depacketizer de WebRTC interpretaría los datos
// suplementarios como parte del OBU.
//
// Los rangos retornados corresponden al frame transformado y cubren el header
// de cada OBU (1 byte) + extensión opcional (1 byte) + LEB128 size (para OBUs
// que no son el último). El payload de cada OBU se cifra completamente.
//
// Referencia: protocol.md "AV1"
func prepareAV1Frame(payload []byte) ([]byte, []frame.Range, error) {
	if len(payload) == 0 {
		return nil, nil, nil
	}

	type parsedOBU struct {
		headerByte byte
		hasExt     bool
		extByte    byte
		sizeBytes  []byte // bytes LEB128 del tamaño (vacío si obu_has_size_field=0)
		data       []byte // payload del OBU
	}

	// Primera pasada: parsear OBUs y descartar los que no se deben cifrar.
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
			// Sin campo de tamaño: el OBU ocupa el resto del frame
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

	// Segunda pasada: construir el frame transformado y calcular rangos.
	var transformed []byte
	var ranges []frame.Range
	writeOffset := 0

	for i, obu := range obus {
		isLast := i == len(obus)-1
		unencryptedStart := writeOffset

		// Header byte: para el último OBU, limpiar obu_has_size_field (bit 1)
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

		// LEB128 size: incluir en todos los OBUs excepto el último.
		// El último OBU ya tiene obu_has_size_field=0, así que no lleva size.
		if !isLast && len(obu.sizeBytes) > 0 {
			transformed = append(transformed, obu.sizeBytes...)
			writeOffset += len(obu.sizeBytes)
		}

		// El header (+ ext + size si no es último) permanece sin cifrar
		unencryptedLen := writeOffset - unencryptedStart
		if unencryptedLen > 0 {
			ranges = append(ranges, frame.Range{
				Offset: unencryptedStart,
				Length: unencryptedLen,
			})
		}

		// Payload del OBU: se cifra completamente
		transformed = append(transformed, obu.data...)
		writeOffset += len(obu.data)
	}

	return transformed, ranges, nil
}

// shouldDropOBU indica si un tipo de OBU debe ser descartado completamente
// durante la transformación del frame.
func shouldDropOBU(obuType byte) bool {
	return obuType == obuTemporalDelimiter ||
		obuType == obuTileList ||
		obuType == obuPadding
}

// decodeLEB128 decodifica un entero LEB128 unsigned (hasta 8 bytes).
// Retorna el valor, el número de bytes consumidos y un posible error.
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
