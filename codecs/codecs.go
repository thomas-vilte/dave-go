// Package codecs handles the codec-aware logic to figure out which bytes
// of a media frame should stay unencrypted under the DAVE protocol.
//
// Each codec has different requirements around what metadata needs to stay
// readable for WebRTC packetizers/depacketizers. The DAVE encryptor is
// codec-aware (knows the structure of each codec), while the decryptor is
// codec-unaware (just uses the unencrypted ranges from the footer).
//
// Reference: protocol.md "Codec Handling":
// "The encrypting frame transformer is codec-aware and processes incoming
// encoded frames from WebRTC to determine which ranges must be left
// unencrypted"
package codecs

import (
	"crypto/cipher"

	"github.com/thomas-vilte/dave-go/frame"
)

// Kind identifies the codec of a media frame.
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

// Encrypt encrypts a media frame in a codec-aware way following the DAVE protocol.
//
// This is the recommended API for the dave/session layer. It handles each codec's
// quirks internally:
//   - H264/H265: retries with an incremented nonce if the ciphertext contains
//     start code sequences (up to 10 attempts).
//   - AV1: transforms the frame first (strips unnecessary OBUs and the size
//     field from the last OBU) then encrypts the transformed frame.
//   - OPUS, VP8, VP9: figures out the unencrypted ranges and encrypts directly.
//
// Reference: protocol.md "Codec Handling"
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

// EncryptWithCipher encrypts a frame using a pre-created cipher (avoids recreating AES per frame).
// Use when the caller already has the cipher cached (e.g. session.Encrypt with cached cipher).
// H264/H265 with start-code retry falls back to Encrypt (requires the key to retry with nonce+1).
func EncryptWithCipher(kind Kind, plaintext []byte, gcm cipher.AEAD, nonce uint32) ([]byte, error) {
	switch kind {
	case CodecAV1:
		transformed, ranges, err := prepareAV1Frame(plaintext)
		if err != nil {
			return nil, err
		}
		return frame.EncryptWithCipher(frame.EncryptWithCipherParams{
			Plaintext:         transformed,
			Cipher:            gcm,
			TruncatedNonce:    nonce,
			UnencryptedRanges: ranges,
		})
	default:
		ranges, err := UnencryptedRanges(kind, plaintext)
		if err != nil {
			return nil, err
		}
		return frame.EncryptWithCipher(frame.EncryptWithCipherParams{
			Plaintext:         plaintext,
			Cipher:            gcm,
			TruncatedNonce:    nonce,
			UnencryptedRanges: ranges,
		})
	}
}

// UnencryptedRanges figures out which portions of a frame payload should stay
// unencrypted depending on the codec.
//
// Returns nil when the whole frame can be encrypted (OPUS, VP9).
// Returns ranges with offset/length when there's metadata that needs to stay
// in plaintext for WebRTC packetizers/depacketizers.
//
// Note: for AV1, this method can't be used directly since the codec requires
// transforming the frame before computing ranges. Use Encrypt instead.
//
// Reference: protocol.md "Codec Handling" and codec-specific sections.
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
