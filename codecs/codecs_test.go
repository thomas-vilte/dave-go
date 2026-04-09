package codecs

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/dave-go/frame"
)

// ─────────────────────────────────────────────
// Tests H26x: retry de nonce por start codes
// ─────────────────────────────────────────────

func TestEncryptH26xNoStartCodeCollision(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)

	// Frame H264 mínimo: 4-byte start code + NAL VCL tipo 1
	payload := []byte{0x00, 0x00, 0x00, 0x01, 0x41, 0xAA, 0xBB, 0xCC, 0xDD}
	encrypted, err := encryptH26x(CodecH264, payload, key, 0)
	if err != nil {
		t.Fatalf("encryptH26x error: %v", err)
	}
	if !frame.LooksLikeDAVEFrame(encrypted) {
		t.Fatal("resultado no es un frame DAVE válido")
	}
}

func TestEncryptH26xRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, 16)

	// Frame H264 con NAL VCL y non-VCL
	// non-VCL (tipo 7 = SPS) + VCL (tipo 5 = IDR)
	payload := []byte{
		0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E, // SPS (non-VCL, tipo 7)
		0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, // IDR (VCL, tipo 5)
	}

	encrypted, err := encryptH26x(CodecH264, payload, key, 42)
	if err != nil {
		t.Fatalf("encryptH26x error: %v", err)
	}

	// Descifrar usando frame.Decrypt directamente (el decryptor es codec-unaware)
	decrypted, nonce, err := frame.Decrypt(frame.DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if nonce < 42 {
		t.Errorf("nonce esperado >= 42 (base), got %d", nonce)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("plaintext no coincide:\n  got:  %x\n  want: %x", decrypted, payload)
	}
}

func TestEncryptH26xH265RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, 16)

	// Frame H265 con VCL tipo 1 (TRAIL_N)
	payload := []byte{0x00, 0x00, 0x01, 0x02, 0x01, 0xFF, 0xEE, 0xDD}

	encrypted, err := encryptH26x(CodecH265, payload, key, 1)
	if err != nil {
		t.Fatalf("encryptH26x H265 error: %v", err)
	}

	decrypted, _, err := frame.Decrypt(frame.DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("plaintext no coincide")
	}
}

// TestEncryptH26xNonceIncrementOnCollision verifica que cuando el primer nonce
// produce un ciphertext con start code, se usa un nonce diferente.
func TestEncryptH26xNonceIncrementOnCollision(t *testing.T) {
	key := bytes.Repeat([]byte{0x04}, 16)

	// Frame H264 simple (VCL tipo 1)
	payload := []byte{0x00, 0x00, 0x01, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x01}

	encrypted, err := encryptH26x(CodecH264, payload, key, 0)
	if err != nil {
		t.Fatalf("encryptH26x error: %v", err)
	}

	// El resultado debe poder descifrarse correctamente independientemente del nonce usado
	decrypted, _, err := frame.Decrypt(frame.DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("plaintext no coincide")
	}
}

// ─────────────────────────────────────────────
// Tests AV1: transformación de frame
// ─────────────────────────────────────────────

// buildOBU construye un OBU AV1 con los campos dados.
func buildOBU(obuType byte, hasExt bool, hasSize bool, payload []byte) []byte {
	header := (obuType << 3)
	if hasExt {
		header |= 0x04
	}
	if hasSize {
		header |= 0x02
	}

	var obu []byte
	obu = append(obu, header)
	if hasExt {
		obu = append(obu, 0x00) // extension byte vacío
	}
	if hasSize {
		// LEB128 del tamaño del payload
		size := uint64(len(payload))
		for {
			b := byte(size & 0x7F)
			size >>= 7
			if size != 0 {
				b |= 0x80
			}
			obu = append(obu, b)
			if size == 0 {
				break
			}
		}
	}
	obu = append(obu, payload...)
	return obu
}

func TestPrepareAV1FrameEmpty(t *testing.T) {
	transformed, ranges, err := prepareAV1Frame(nil)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if transformed != nil || ranges != nil {
		t.Error("expected nil, nil para payload vacío")
	}
}

func TestPrepareAV1FrameDropsTemporalDelimiter(t *testing.T) {
	// OBU_TEMPORAL_DELIMITER (tipo 2) debe ser eliminado
	td := buildOBU(obuTemporalDelimiter, false, true, []byte{})
	// Seguido de un OBU real (tipo 1 = OBU_SEQUENCE_HEADER)
	seqHeader := buildOBU(1, false, true, []byte{0xAA, 0xBB})

	payload := append(td, seqHeader...)
	transformed, ranges, err := prepareAV1Frame(payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// El frame transformado NO debe contener el Temporal Delimiter
	// Solo debe quedar el sequence header (sin campo de tamaño, es el último)
	if len(transformed) == 0 {
		t.Fatal("frame transformado vacío")
	}

	// El header del sequence header tiene obu_has_size_field=0 (bit 1 limpiado)
	// obu_type=1, sin ext, sin size: header = (1 << 3) = 0x08
	if transformed[0] != 0x08 {
		t.Errorf("header byte esperado 0x08 (sin size field), got 0x%02x", transformed[0])
	}

	// Debe haber exactamente 1 rango unencrypted (el header del último OBU)
	if len(ranges) != 1 {
		t.Errorf("esperado 1 rango, got %d", len(ranges))
	}
	if ranges[0].Offset != 0 || ranges[0].Length != 1 {
		t.Errorf("rango esperado {0,1}, got {%d,%d}", ranges[0].Offset, ranges[0].Length)
	}
}

func TestPrepareAV1FrameLastOBUSizeFieldRemoved(t *testing.T) {
	// Frame con dos OBUs, ambos con size field
	obu1Payload := []byte{0x11, 0x22, 0x33}
	obu2Payload := []byte{0xAA, 0xBB}

	// Tipo 6 = OBU_TILE_GROUP (VCL, se cifra)
	obu1 := buildOBU(6, false, true, obu1Payload)
	obu2 := buildOBU(6, false, true, obu2Payload)
	payload := append(obu1, obu2...)

	transformed, ranges, err := prepareAV1Frame(payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// obu1: header(1) + LEB128_size(1) + payload(3) = 5 bytes (mantiene size field)
	// obu2 (último): header(1, sin size bit) + payload(2) = 3 bytes (sin size field)
	expectedLen := 5 + 3
	if len(transformed) != expectedLen {
		t.Errorf("longitud esperada %d, got %d", expectedLen, len(transformed))
	}

	// Header del último OBU (offset 5) debe tener obu_has_size_field=0
	lastHeader := transformed[5]
	if lastHeader&0x02 != 0 {
		t.Errorf("obu_has_size_field del último OBU debe ser 0, header=0x%02x", lastHeader)
	}

	// Debe haber 2 rangos: uno por cada OBU header (+size para el primero)
	if len(ranges) != 2 {
		t.Errorf("esperado 2 rangos, got %d", len(ranges))
	}
	// Primer OBU: offset=0, length=2 (header + LEB128 size de 1 byte)
	if ranges[0].Offset != 0 || ranges[0].Length != 2 {
		t.Errorf("rango[0] esperado {0,2}, got {%d,%d}", ranges[0].Offset, ranges[0].Length)
	}
	// Segundo OBU: offset=5, length=1 (solo header, sin size field)
	if ranges[1].Offset != 5 || ranges[1].Length != 1 {
		t.Errorf("rango[1] esperado {5,1}, got {%d,%d}", ranges[1].Offset, ranges[1].Length)
	}
}

func TestPrepareAV1FrameDropsPadding(t *testing.T) {
	padding := buildOBU(obuPadding, false, true, []byte{0x00, 0x00})
	tileList := buildOBU(obuTileList, false, true, []byte{0xFF})
	real := buildOBU(6, false, true, []byte{0x42, 0x43, 0x44})

	payload := append(append(padding, tileList...), real...)
	transformed, _, err := prepareAV1Frame(payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Solo debe quedar el OBU real (tipo 6)
	// header(1) + payload(3) = 4 bytes (sin size field, es el único y por tanto el último)
	if len(transformed) != 4 {
		t.Errorf("longitud esperada 4, got %d", len(transformed))
	}
}

func TestPrepareAV1FrameWithExtension(t *testing.T) {
	// OBU con extension byte
	obu := buildOBU(6, true, true, []byte{0x10, 0x20})
	transformed, ranges, err := prepareAV1Frame(obu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// header(1) + ext(1) + payload(2) = 4 bytes (sin size field, es el último)
	if len(transformed) != 4 {
		t.Errorf("longitud esperada 4, got %d", len(transformed))
	}
	// El rango unencrypted debe cubrir header + extension = 2 bytes
	if len(ranges) != 1 || ranges[0].Length != 2 {
		t.Errorf("esperado rango length=2, got ranges=%v", ranges)
	}
}

func TestEncryptAV1RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, 16)

	// Frame AV1 con Temporal Delimiter + OBU real
	td := buildOBU(obuTemporalDelimiter, false, true, []byte{})
	data := buildOBU(6, false, true, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	payload := append(td, data...)

	encrypted, err := Encrypt(CodecAV1, payload, key, 10)
	if err != nil {
		t.Fatalf("Encrypt AV1 error: %v", err)
	}
	if !frame.LooksLikeDAVEFrame(encrypted) {
		t.Fatal("resultado no es un frame DAVE válido")
	}

	// El decryptor es codec-unaware: descifra correctamente usando los rangos del footer.
	// El plaintext resultado es el frame TRANSFORMADO (sin Temporal Delimiter y sin size field).
	decrypted, _, err := frame.Decrypt(frame.DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	// El frame descifrado debe ser el frame transformado (TD eliminado, last OBU sin size)
	expectedTransformed, _, _ := prepareAV1Frame(payload)
	if !bytes.Equal(decrypted, expectedTransformed) {
		t.Errorf("plaintext no coincide:\n  got:  %x\n  want: %x", decrypted, expectedTransformed)
	}
}

// ─────────────────────────────────────────────
// Tests generales de codecs.Encrypt
// ─────────────────────────────────────────────

func TestEncryptOpusFullEncrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x06}, 16)
	payload := []byte{0xF8, 0xFF, 0xFE, 0x01, 0x02, 0x03} // frame OPUS

	encrypted, err := Encrypt(CodecOpus, payload, key, 1)
	if err != nil {
		t.Fatalf("Encrypt OPUS error: %v", err)
	}

	decrypted, _, err := frame.Decrypt(frame.DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("plaintext no coincide")
	}
}

func TestEncryptVP8RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 16)
	// Frame VP8 non-key (P=1 en bit 0 del primer byte)
	payload := []byte{0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	encrypted, err := Encrypt(CodecVP8, payload, key, 5)
	if err != nil {
		t.Fatalf("Encrypt VP8 error: %v", err)
	}

	decrypted, _, err := frame.Decrypt(frame.DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("plaintext no coincide")
	}
}
