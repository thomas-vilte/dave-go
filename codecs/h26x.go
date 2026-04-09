package codecs

import (
	"bytes"

	"github.com/thomas-vilte/dave-go/frame"
)

// maxH26xRetries es el número máximo de reintentos de nonce para evitar
// colisiones con secuencias start code en el ciphertext H264/H265.
const maxH26xRetries = 10

// encryptH26x cifra un frame H264 o H265 con lógica de reintento de nonce.
//
// Después de cada intento de cifrado, escanea los bytes cifrados y el footer
// buscando secuencias start code (0x000001 o 0x00000001). Si se detecta una
// colisión, incrementa el nonce y reintenta hasta maxH26xRetries veces.
//
// Los bytes unencrypted (non-VCL NAL units) se excluyen del escaneo porque
// contienen start codes válidos por diseño.
//
// Referencia: protocol.md "H264 & H265":
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

		// Extraer solo los bytes cifrados (excluir los rangos unencrypted)
		// para verificar colisiones. Los non-VCL NAL units tienen start codes
		// por diseño y no deben incluirse en la verificación.
		interleavedFrame := encrypted[:len(plaintext)]
		ciphertextBytes := frame.ExtractCiphertext(interleavedFrame, ranges)
		footer := encrypted[len(plaintext):]

		if !hasStartCodeSequence(ciphertextBytes) && !hasStartCodeSequence(footer) {
			return encrypted, nil
		}
		lastResult = encrypted
	}

	// Si se agotaron los reintentos, retornar el último resultado disponible.
	return lastResult, nil
}

// h26xRanges determina los rangos unencrypted para frames H264 y H265.
//
// Proceso:
//  1. Itera las NAL units del frame buscando start codes (0x000001 o 0x00000001)
//  2. Clasifica cada NAL unit como VCL (video coding layer) o non-VCL
//  3. Las NAL units VCL se cifran completamente (contienen datos de video)
//  4. Las NAL units non-VCL permanecen sin cifrar (metadata leído por packetizer/depacketizer)
//
// Nota adicional: después del cifrado, se debe escanear el ciphertext y los datos
// suplementarios para asegurar que no aparezca una secuencia start code (0x000001 o
// 0x00000001). Si aparece, se incrementa el nonce y se reintenta el cifrado (hasta 10
// veces). Esto evita que el packetizer/depacketizer interprete ciphertext como NAL units.
//
// Referencia: protocol.md "H264 & H265":
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
		// Buscar start code: 3 bytes (0x000001) o 4 bytes (0x00000001)
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

		// Determinar tipo de NAL unit
		nalHeader := payload[nalStart]
		var nalType byte
		if kind == CodecH264 {
			// H264: los 5 bits menos significativos del primer byte
			nalType = nalHeader & 0x1F
		} else {
			// H265: bits 1-6 del primer byte (shift 1, mask 0x3F)
			nalType = (nalHeader >> 1) & 0x3F
		}

		// VCL NAL units contienen datos de video y se cifran completamente
		// H264: tipos 1-5 son VCL
		// H265: tipos 0-31 son VCL (BLA, CRA, IDR, etc.)
		isVCL := false
		if kind == CodecH264 {
			isVCL = nalType >= 1 && nalType <= 5
		} else {
			isVCL = nalType <= 31
		}

		// Encontrar el inicio de la siguiente NAL unit
		nextOffset := findNextStartCode(payload, nalStart)
		if nextOffset == -1 {
			nextOffset = len(payload)
		}

		// Las NAL units non-VCL permanecen sin cifrar
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

// findNextStartCode busca el próximo start code H26x a partir de `from`.
// Retorna -1 si no encuentra ninguno.
func findNextStartCode(payload []byte, from int) int {
	for i := from; i < len(payload)-3; i++ {
		if payload[i] == 0 && payload[i+1] == 0 && (payload[i+2] == 1 || (payload[i+2] == 0 && payload[i+3] == 1)) {
			return i
		}
	}
	return -1
}

// hasStartCodeSequence verifica si los datos contienen una secuencia start code H26x.
// Se usa durante el cifrado para detectar colisiones y reintentar con otro nonce.
//
// Referencia: protocol.md "H264 & H265":
// "If a start code sequence is encountered the nonce is incremented and
// encryption is re-attempted"
func hasStartCodeSequence(data []byte) bool {
	return bytes.Contains(data, []byte{0x00, 0x00, 0x01}) ||
		bytes.Contains(data, []byte{0x00, 0x00, 0x00, 0x01})
}

// nonceForEncryption calcula el nonce para un intento de cifrado.
// En H26x, si el cifrado produce start codes en el ciphertext, se incrementa
// el nonce y se reintenta (hasta 10 veces).
func nonceForEncryption(baseNonce uint32, attempt int) uint32 {
	return baseNonce + uint32(attempt)
}
