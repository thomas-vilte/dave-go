package frame

// ValidateRanges verifica que los rangos unencrypted sean válidos:
//   - offsets y lengths no negativos
//   - no se salen del tamaño del frame
//   - están ordenados por offset ascendente
//   - no se solapan entre sí
//
// Esta validación es crítica porque rangos inválidos podrían causar
// corrupción de memoria o bypass de cifrado.
//
// Referencia: protocol.md "Protocol Frame Check":
// "Must be ordered by ascending range offset"
// "Must be distinct and not overlapping"
// "Must not overflow the total size of the interleaved media frame"
func ValidateRanges(ranges []Range, size int) error {
	prevEnd := 0
	for i, r := range ranges {
		if r.Offset < 0 || r.Length < 0 {
			return ErrInvalidRanges
		}
		if r.Offset+r.Length > size {
			return ErrInvalidRanges
		}
		if i > 0 && r.Offset < prevEnd {
			return ErrInvalidRanges
		}
		prevEnd = r.Offset + r.Length
	}
	return nil
}

// ContiguousPlaintextSize calcula cuántos bytes del frame serán cifrados,
// es decir, el tamaño total menos los bytes en los rangos unencrypted.
func ContiguousPlaintextSize(frameSize int, ranges []Range) int {
	size := frameSize
	for _, r := range ranges {
		size -= r.Length
	}
	return size
}

// ReconstructPlaintext reconstruye el plaintext original a partir del frame
// interleaved y los bytes descifrados.
//
// El frame interleaved tiene los bytes unencrypted en sus posiciones originales
// y bytes cifrados en las posiciones cifradas. Esta función reemplaza las
// posiciones cifradas con los bytes descifrados.
//
// Diagrama:
//
//	Interleaved: [UUccccUUcccc]  (U=unencrypted original, c=ciphertext)
//	Decrypted:   [CCCC]          (bytes descifrados concatenados)
//	Resultado:   [UUCCCCUUCCCC]  (plaintext original reconstruido)
func ReconstructPlaintext(interleaved []byte, decrypted []byte, ranges []Range) []byte {
	out := make([]byte, len(interleaved))
	copy(out, interleaved)

	cipherPos := 0
	last := 0
	for _, r := range ranges {
		// Copiar decrypted en la zona entre el último rango y este rango
		if r.Offset > last {
			n := r.Offset - last
			copy(out[last:r.Offset], decrypted[cipherPos:cipherPos+n])
			cipherPos += n
		}
		last = r.Offset + r.Length
	}
	// Copiar el resto del decrypted después del último rango
	if last < len(interleaved) {
		copy(out[last:], decrypted[cipherPos:])
	}
	return out
}

// ExtractCiphertext extrae los bytes cifrados del frame interleaved,
// es decir, todos los bytes que NO están en los rangos unencrypted.
//
// Diagrama:
//
//	Interleaved: [UUccccUUcccc]  (U=unencrypted, c=ciphertext)
//	Retornado:   [cccccccc]      (solo bytes cifrados concatenados)
func ExtractCiphertext(interleaved []byte, ranges []Range) []byte {
	size := ContiguousPlaintextSize(len(interleaved), ranges)
	out := make([]byte, 0, size)
	last := 0
	for _, r := range ranges {
		if r.Offset > last {
			out = append(out, interleaved[last:r.Offset]...)
		}
		last = r.Offset + r.Length
	}
	if last < len(interleaved) {
		out = append(out, interleaved[last:]...)
	}
	return out
}
