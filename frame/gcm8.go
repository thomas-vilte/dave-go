// AES-128-GCM with a tag truncated to 64 bits (8 bytes).
//
// Go's standard library only supports 12-16 byte tags via cipher.NewGCMWithTagSize.
// DAVE requires 8-byte tags per protocol.md "Truncated authentication tag":
// "AES128-GCM authentication tags are truncated to 64-bits"
//
// Strategy: use the standard cipher.NewGCM internally and truncate the tag to 8 bytes.
// For Open: decrypt first (XOR with keystream) then verify the tag by re-encrypting
// the resulting plaintext.
//
// Complies with NIST SP 800-38D Appendix C for 64-bit tags.
package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// NewGCM8 creates an AES-128-GCM instance with the tag truncated to 8 bytes.
// Exported so callers can cache the cipher and avoid recreating it on every frame.
func NewGCM8(key []byte) (cipher.AEAD, error) {
	return newGCM8(key)
}

// newGCM8 creates an AES-128-GCM instance with the tag truncated to 8 bytes.
func newGCM8(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	inner, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &gcm8{inner: inner}, nil
}

// gcm8 implements cipher.AEAD with an 8-byte tag.
type gcm8 struct {
	inner cipher.AEAD
}

func (g *gcm8) NonceSize() int { return g.inner.NonceSize() }
func (g *gcm8) Overhead() int  { return 8 }

// Seal encrypts and authenticates the plaintext, returning ciphertext + tag(8 bytes).
func (g *gcm8) Seal(dst, nonce, plaintext, aad []byte) []byte {
	sealed := g.inner.Seal(dst, nonce, plaintext, aad)
	// sealed = dst + ciphertext + tag(16 bytes)
	// Truncate tag to 8 bytes
	tagStart := len(sealed) - 16
	return append(sealed[:tagStart], sealed[tagStart:tagStart+8]...)
}

// Open verifies the truncated tag (8 bytes) and decrypts the ciphertext.
//
// Process:
//  1. Extract ciphertext and truncated tag
//  2. Decrypt using keystream (GCM with zero plaintext)
//  3. Verify the tag by re-encrypting the plaintext and comparing
func (g *gcm8) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < 8 {
		return nil, ErrAuthTagMismatch
	}

	data := ciphertext[:len(ciphertext)-8]
	receivedTag := ciphertext[len(ciphertext)-8:]

	// Decrypt: keystream = Seal(nonce, zeros, aad)
	keystream := g.inner.Seal(nil, nonce, make([]byte, len(data)), aad)
	keystream = keystream[:len(data)]

	plaintext := make([]byte, len(data))
	for i := range data {
		plaintext[i] = data[i] ^ keystream[i]
	}

	// Verify tag: re-encrypt the plaintext and compare the first 8 bytes
	fullSealed := g.inner.Seal(nil, nonce, plaintext, aad)
	fullTag := fullSealed[len(fullSealed)-16:]
	if !constantTimeEqual(receivedTag, fullTag[:8]) {
		return nil, ErrAuthTagMismatch
	}

	return append(dst, plaintext...), nil
}

// constantTimeEqual compares two byte slices in constant time.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

var _ cipher.AEAD = (*gcm8)(nil)
