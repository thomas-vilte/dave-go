package frame

import (
	"encoding/binary"
	"fmt"
)

// Encrypt cifra un frame de media según el formato DAVE.
//
// Proceso:
//  1. Valida que la key sea de 16 bytes (AES-128)
//  2. Valida que los rangos unencrypted sean válidos (ordenados, no solapados, dentro del frame)
//  3. Extrae los bytes que van a ser cifrados (todo lo que NO está en los rangos unencrypted)
//  4. Construye el AAD con los bytes unencrypted (protocol.md: "All of the unencrypted ranges
//     from the frame are joined together and included as additional data")
//  5. Cifra con AES-128-GCM (tag truncado a 8 bytes) usando el nonce expandido a 96 bits
//  6. Construye el frame interleaved: copia el frame original y reemplaza las zonas cifradas
//     con el ciphertext
//  7. Construye el footer: tag(8) + nonce(ULEB128) + ranges(ULEB128 pairs) + supplSize + 0xFAFA
//
// Referencia: protocol.md "Payload Format", "Interleaved protocol media frame"
func Encrypt(params EncryptParams) ([]byte, error) {
	if len(params.Key) != 16 {
		return nil, ErrInvalidKeyLength
	}
	if err := ValidateRanges(params.UnencryptedRanges, len(params.Plaintext)); err != nil {
		return nil, err
	}

	gcm, err := newGCM8(params.Key)
	if err != nil {
		return nil, err
	}

	// Nonce expandido a 96 bits: 8 bytes cero + 4 bytes del truncated nonce.
	// libdave copia el uint32 truncado byte a byte al final del nonce (memcpy),
	// lo que en plataformas little-endian produce un layout little-endian.
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint32(nonce[8:], params.TruncatedNonce)

	// Extraer bytes cifrados (todo lo que NO está en rangos unencrypted)
	ciphertext := ExtractCiphertext(params.Plaintext, params.UnencryptedRanges)

	// AAD = concatenación de los bytes unencrypted en orden
	// Referencia: protocol.md "Interleaved protocol media frame":
	// "All of the (potentially discontiguous) unencrypted ranges from the frame are joined
	// together and included as additional data to be authenticated by the AEAD ciphersuite"
	aad := buildAAD(params.Plaintext, params.UnencryptedRanges)

	// Cifrar con AES-128-GCM (tag truncado a 8 bytes)
	sealed := gcm.Seal(nil, nonce, ciphertext, aad)
	ciphertextOut := sealed[:len(sealed)-8]
	tag := sealed[len(sealed)-8:]

	// Cuando no hay rangos unencrypted (p. ej. Opus), todo el frame interleaved
	// debe ser ciphertext. Si usamos el plaintext como base, buildInterleaved no
	// reemplaza nada y termina devolviendo el frame original sin cifrar.
	baseFrame := params.Plaintext
	if len(params.UnencryptedRanges) == 0 {
		baseFrame = ciphertextOut
	}

	// Construir frame interleaved: frame original con zonas cifradas reemplazadas por ciphertext
	out := buildInterleaved(baseFrame, params.UnencryptedRanges, ciphertextOut)

	// Construir footer
	out = append(out, tag...)

	nonceBytes := EncodeULEB128(params.TruncatedNonce)
	out = append(out, nonceBytes...)

	var rangesData []byte
	for _, r := range params.UnencryptedRanges {
		rangesData = append(rangesData, EncodeULEB128(uint32(r.Offset))...)
		rangesData = append(rangesData, EncodeULEB128(uint32(r.Length))...)
	}
	out = append(out, rangesData...)

	// Suppl. Size incluye todo el contenido suplementario:
	// tag(8) + nonce(ULEB128) + rangesData + este byte(1) + magic(2)
	// Referencia: protocol.md "Protocol supplemental data size"
	supplSize := uint8(8 + len(nonceBytes) + len(rangesData) + 1 + 2)
	out = append(out, supplSize)
	out = append(out, 0xFA, 0xFA)

	return out, nil
}

// Decrypt descifra un frame DAVE y retorna el plaintext original junto con el nonce.
//
// Proceso:
//  1. Valida que la key sea de 16 bytes
//  2. Verifica que el frame pase el protocol frame check (magic marker 0xFAFA)
//  3. Parsea el footer para extraer tag, nonce, y rangos unencrypted
//  4. Extrae los bytes cifrados del frame interleaved (posiciones fuera de los rangos)
//  5. Construye el AAD con los bytes unencrypted del frame interleaved
//  6. Descifra con AES-128-GCM verificando el tag de autenticación
//  7. Reconstruye el plaintext original re-insertando el decrypted en las posiciones cifradas
//
// Referencia: protocol.md "Payload Format", "Protocol Frame Check"
func Decrypt(params DecryptParams) ([]byte, uint32, error) {
	if len(params.Key) != 16 {
		return nil, 0, ErrInvalidKeyLength
	}
	if !LooksLikeDAVEFrame(params.Ciphertext) {
		return nil, 0, ErrFrameTooShort
	}

	parsed, err := Parse(params.Ciphertext)
	if err != nil {
		return nil, 0, err
	}

	gcm, err := newGCM8(params.Key)
	if err != nil {
		return nil, 0, err
	}

	// Expandir nonce truncado (32 bits) a nonce completo (96 bits)
	// Referencia: protocol.md "Truncated synchronization nonce":
	// "The full-size nonce is produced by writing the truncated nonce to the 4 least
	// significant bytes and making the 8 most significant bytes all zero"
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint32(nonce[8:], parsed.TruncatedNonce)

	// Extraer ciphertext del frame interleaved (bytes fuera de los rangos unencrypted)
	ciphertext := ExtractCiphertext(parsed.InterleavedFrame, parsed.UnencryptedRanges)

	// AAD = bytes unencrypted del frame interleaved (mismos que se usaron en Encrypt)
	aad := buildAAD(parsed.InterleavedFrame, parsed.UnencryptedRanges)

	// Reconstruir el sealed message: ciphertext + tag
	sealed := append(ciphertext, parsed.Tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, 0, err
	}

	// Reconstruir plaintext original: insertar decrypted en las posiciones cifradas
	result := ReconstructPlaintext(parsed.InterleavedFrame, plaintext, parsed.UnencryptedRanges)
	return result, parsed.TruncatedNonce, nil
}

// LooksLikeDAVEFrame verifica rápidamente si un packet podría ser un frame DAVE
// chequeando el magic marker 0xFAFA en la posición esperada y el tamaño mínimo.
//
// El tamaño mínimo de 11 bytes corresponde a:
// tag(8) + nonce_mínimo(1) + supplSize(1) + magic(2) = 12 bytes de footer
// pero con 0 bytes de interleaved frame, el total mínimo es 12.
// Usamos 11 como umbral conservador para el check rápido.
//
// Referencia: protocol.md "Protocol Frame Check"
func LooksLikeDAVEFrame(packet []byte) bool {
	if len(packet) < 11 {
		return false
	}
	if packet[len(packet)-2] != 0xFA || packet[len(packet)-1] != 0xFA {
		return false
	}
	return true
}

// buildAAD construye el Additional Authenticated Data concatenando los bytes
// de los rangos unencrypted del frame en orden ascendente.
//
// Estos bytes se incluyen en el AAD para que el SFU no pueda modificarlos sin
// invalidar la autenticación, pero permanecen en plaintext para que los
// packetizers/depacketizers de WebRTC puedan leerlos.
//
// Referencia: protocol.md "Interleaved protocol media frame":
// "All of the (potentially discontiguous) unencrypted ranges from the frame are
// joined together and included as additional data to be authenticated"
func buildAAD(frame []byte, ranges []Range) []byte {
	aad := make([]byte, 0, len(frame))
	for _, r := range ranges {
		aad = append(aad, frame[r.Offset:r.Offset+r.Length]...)
	}
	return aad
}

// buildInterleaved construye el frame interleaved copiando el frame original
// y reemplazando las posiciones cifradas (fuera de los rangos unencrypted)
// con el ciphertext correspondiente.
//
// Diagrama del proceso:
//
//	Original:  [UUCCCCUUCCCC]  (U=unencrypted, C=cifrar)
//	Ciphertext:[cccc]           (solo los bytes C concatenados)
//	Resultado: [UUccccUUccccc]  (ciphertext re-insertado en posiciones C)
func buildInterleaved(original []byte, ranges []Range, ciphertext []byte) []byte {
	out := make([]byte, len(original))
	copy(out, original)

	cipherPos := 0
	last := 0
	for _, r := range ranges {
		// Copiar ciphertext en la zona entre el último rango y este rango
		if r.Offset > last {
			n := r.Offset - last
			copy(out[last:r.Offset], ciphertext[cipherPos:cipherPos+n])
			cipherPos += n
		}
		last = r.Offset + r.Length
	}
	// Copiar el resto del ciphertext después del último rango
	if last < len(original) {
		copy(out[last:], ciphertext[cipherPos:])
	}
	return out
}

// Parse analiza un frame DAVE completo y extrae sus componentes del footer.
//
// El footer se ubica al final del packet y contiene:
//  1. Truncated authentication tag (8 bytes)
//  2. Truncated synchronization nonce (ULEB128 variable)
//  3. Unencrypted range offset/length pairs (ULEB128 variable)
//  4. Supplemental data size (1 byte)
//  5. Magic marker 0xFAFA (2 bytes)
//
// El supplemental size indica el tamaño de todo el contenido desde el tag
// hasta el magic marker inclusive.
//
// Referencia: protocol.md "Payload Format" diagram
func Parse(packet []byte) (*ParsedFrame, error) {
	if len(packet) < 11 {
		return nil, fmt.Errorf("packet too short: %w", ErrFrameTooShort)
	}
	if packet[len(packet)-2] != 0xFA || packet[len(packet)-1] != 0xFA {
		return nil, ErrInvalidMagicMarker
	}

	supplSize := int(packet[len(packet)-3])
	if supplSize < 11 || supplSize > len(packet) {
		return nil, fmt.Errorf("supplemental size %d out of range: %w", supplSize, ErrInvalidSupplementalSize)
	}

	// El frame interleaved ocupa todo el packet menos el supplemental data
	footerStart := len(packet) - supplSize
	if footerStart < 0 {
		return nil, fmt.Errorf("invalid footer position: %w", ErrInvalidSupplementalSize)
	}

	// El footer data es todo menos los 3 bytes finales (supplSize + magic)
	footer := packet[footerStart : len(packet)-3]
	expectedFooterLen := supplSize - 3
	if len(footer) != expectedFooterLen {
		return nil, fmt.Errorf("footer length mismatch: %w", ErrInvalidSupplementalSize)
	}

	pos := 0

	// 1. Truncated authentication tag (8 bytes)
	tag := footer[pos : pos+8]
	pos += 8

	// 2. Truncated synchronization nonce (ULEB128)
	nonce, n, err := DecodeULEB128(footer[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	// 3. Unencrypted range offset/length pairs (ULEB128)
	var ranges []Range
	rangesData := footer[pos:]
	for len(rangesData) > 0 {
		offset, n1, err := DecodeULEB128(rangesData)
		if err != nil {
			break
		}
		rangesData = rangesData[n1:]
		length, n2, err := DecodeULEB128(rangesData)
		if err != nil {
			break
		}
		rangesData = rangesData[n2:]
		ranges = append(ranges, Range{
			Offset: int(offset),
			Length: int(length),
		})
	}

	interleaved := packet[:footerStart]
	if err := ValidateRanges(ranges, len(interleaved)); err != nil {
		return nil, err
	}

	return &ParsedFrame{
		InterleavedFrame:  interleaved,
		Tag:               tag,
		TruncatedNonce:    nonce,
		UnencryptedRanges: ranges,
		SupplementalSize:  uint8(supplSize),
	}, nil
}
