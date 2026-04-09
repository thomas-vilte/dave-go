// Implementación de AES-128-GCM con tag truncado a 64 bits (8 bytes).
//
// Go estándar solo permite tags de 12-16 bytes vía cipher.NewGCMWithTagSize.
// DAVE requiere tags de 8 bytes según protocol.md "Truncated authentication tag":
// "AES128-GCM authentication tags are truncated to 64-bits"
//
// Estrategia: usar cipher.NewGCM estándar internamente y truncar el tag a 8 bytes.
// Para Open: desencriptar primero (XOR con keystream) y luego verificar el tag
// re-encriptando el plaintext resultante.
//
// Cumple con NIST SP 800-38D Appendix C para tags de 64 bits.
package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// newGCM8 crea una instancia de AES-128-GCM con tag truncado a 8 bytes.
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

// gcm8 implementa cipher.AEAD con tag de 8 bytes.
type gcm8 struct {
	inner cipher.AEAD
}

func (g *gcm8) NonceSize() int { return g.inner.NonceSize() }
func (g *gcm8) Overhead() int  { return 8 }

// Seal cifra y autentica el plaintext, retornando ciphertext + tag(8 bytes).
func (g *gcm8) Seal(dst, nonce, plaintext, aad []byte) []byte {
	sealed := g.inner.Seal(dst, nonce, plaintext, aad)
	// sealed = dst + ciphertext + tag(16 bytes)
	// Truncar tag a 8 bytes
	tagStart := len(sealed) - 16
	return append(sealed[:tagStart], sealed[tagStart:tagStart+8]...)
}

// Open verifica el tag truncado (8 bytes) y descifra el ciphertext.
//
// Proceso:
//  1. Extraer ciphertext y tag truncado
//  2. Desencriptar usando keystream (GCM con plaintext de ceros)
//  3. Verificar el tag re-encriptando el plaintext y comparando
func (g *gcm8) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < 8 {
		return nil, ErrAuthTagMismatch
	}

	data := ciphertext[:len(ciphertext)-8]
	receivedTag := ciphertext[len(ciphertext)-8:]

	// Desencriptar: keystream = Seal(nonce, zeros, aad)
	keystream := g.inner.Seal(nil, nonce, make([]byte, len(data)), aad)
	keystream = keystream[:len(data)]

	plaintext := make([]byte, len(data))
	for i := range data {
		plaintext[i] = data[i] ^ keystream[i]
	}

	// Verificar tag: re-encriptar el plaintext y comparar los primeros 8 bytes
	fullSealed := g.inner.Seal(nil, nonce, plaintext, aad)
	fullTag := fullSealed[len(fullSealed)-16:]
	if !constantTimeEqual(receivedTag, fullTag[:8]) {
		return nil, ErrAuthTagMismatch
	}

	return append(dst, plaintext...), nil
}

// constantTimeEqual compara dos slices de bytes en tiempo constante.
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
