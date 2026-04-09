// Package codecs implementa la lógica codec-aware para determinar qué bytes
// de un frame de media deben permanecer sin cifrar según el protocolo DAVE.
//
// Cada codec tiene requisitos distintos sobre qué metadata debe permanecer
// accesible para los packetizers/depacketizers de WebRTC. El encryptor DAVE
// es codec-aware (conoce la estructura de cada codec), mientras que el
// decryptor es codec-unaware (usa los rangos unencrypted del footer).
//
// Referencia: protocol.md "Codec Handling":
// "The encrypting frame transformer is codec-aware and processes incoming
// encoded frames from WebRTC to determine which ranges must be left
// unencrypted"
package codecs

import "github.com/thomas-vilte/dave-go/frame"

// Kind identifica el codec de un frame de media.
type Kind uint8

const (
	CodecUnknown Kind = iota
	CodecOpus
	CodecVP8
	CodecVP9
	CodecH264
	CodecH265
	CodecAV1
)

// Encrypt cifra un frame de media de forma codec-aware según el protocolo DAVE.
//
// Es la API recomendada para la capa dave/session. Maneja las particularidades
// de cada codec internamente:
//   - H264/H265: reintenta con nonce incrementado si el ciphertext contiene
//     start code sequences (hasta 10 intentos).
//   - AV1: transforma el frame primero (elimina OBUs innecesarios y el campo
//     de tamaño del último OBU) y luego cifra el frame transformado.
//   - OPUS, VP8, VP9: calcula los rangos unencrypted y cifra directamente.
//
// Referencia: protocol.md "Codec Handling"
func Encrypt(kind Kind, plaintext, key []byte, nonce uint32) ([]byte, error) {
	switch kind {
	case CodecH264, CodecH265:
		return encryptH26x(kind, plaintext, key, nonce)
	case CodecAV1:
		transformed, ranges, err := prepareAV1Frame(plaintext)
		if err != nil {
			return nil, err
		}
		return frame.Encrypt(frame.EncryptParams{
			Plaintext:         transformed,
			Key:               key,
			TruncatedNonce:    nonce,
			UnencryptedRanges: ranges,
		})
	default:
		ranges, err := UnencryptedRanges(kind, plaintext)
		if err != nil {
			return nil, err
		}
		return frame.Encrypt(frame.EncryptParams{
			Plaintext:         plaintext,
			Key:               key,
			TruncatedNonce:    nonce,
			UnencryptedRanges: ranges,
		})
	}
}

// UnencryptedRanges determina qué porciones del payload de un frame deben
// permanecer sin cifrar según el codec.
//
// Retorna nil cuando todo el frame puede ser cifrado (OPUS, VP9).
// Retorna rangos con offset/length cuando hay metadata que debe permanecer
// en plaintext para los packetizers/depacketizers de WebRTC.
//
// Nota: para AV1, este método no puede usarse directamente porque el codec
// requiere transformar el frame antes de calcular los rangos. Usar Encrypt
// en su lugar.
//
// Referencia: protocol.md "Codec Handling" y secciones específicas por codec.
func UnencryptedRanges(kind Kind, payload []byte) ([]frame.Range, error) {
	switch kind {
	case CodecOpus, CodecVP9:
		return nil, nil
	case CodecVP8:
		return vp8Ranges(payload)
	case CodecH264, CodecH265:
		return h26xRanges(kind, payload)
	default:
		return nil, nil
	}
}
