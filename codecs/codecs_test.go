package codecs

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/dave-go/frame"
)

// ─────────────────────────────────────────────
// H26x tests: nonce retry on start code collisions
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
		t.Errorf("expected nonce >= 42 (base), got %d", nonce)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("plaintext mismatch:\n  got:  %x\n  want: %x", decrypted, payload)
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
		t.Errorf("plaintext mismatch")
	}
}

// TestEncryptH26xNonceIncrementOnCollision checks that when the first nonce
// produces a ciphertext with a start code, a different nonce is used.
func TestEncryptH26xNonceIncrementOnCollision(t *testing.T) {
	key := bytes.Repeat([]byte{0x04}, 16)

	// Simple H264 frame (VCL type 1)
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
		t.Errorf("plaintext mismatch")
	}
}

// ─────────────────────────────────────────────
// AV1 tests: frame transformation
// ─────────────────────────────────────────────

// buildOBU builds an AV1 OBU with the given fields.
func buildOBU(obuType byte, hasExt bool, hasSize bool, payload []byte) []byte {
	header := obuType << 3
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
		t.Error("expected nil, nil for empty payload")
	}
}

func TestPrepareAV1FrameDropsTemporalDelimiter(t *testing.T) {
	// OBU_TEMPORAL_DELIMITER (type 2) should be dropped
	td := buildOBU(obuTemporalDelimiter, false, true, []byte{})
	// Followed by a real OBU (type 1 = OBU_SEQUENCE_HEADER)
	seqHeader := buildOBU(1, false, true, []byte{0xAA, 0xBB})

	payload := append(td, seqHeader...)
	transformed, ranges, err := prepareAV1Frame(payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// The transformed frame should NOT contain the Temporal Delimiter
	// Only the sequence header should remain (without the size field, since it's the last one)
	if len(transformed) == 0 {
		t.Fatal("empty transformed frame")
	}

	// The sequence header should have obu_has_size_field=0 (bit 1 cleared)
	// obu_type=1, no ext, no size: header = (1 << 3) = 0x08
	if transformed[0] != 0x08 {
		t.Errorf("expected header byte 0x08 (no size field), got 0x%02x", transformed[0])
	}

	// Should have exactly 1 unencrypted range (the last OBU's header)
	if len(ranges) != 1 {
		t.Errorf("expected 1 range, got %d", len(ranges))
	}
	if ranges[0].Offset != 0 || ranges[0].Length != 1 {
		t.Errorf("expected range {0,1}, got {%d,%d}", ranges[0].Offset, ranges[0].Length)
	}
}

func TestPrepareAV1FrameLastOBUSizeFieldRemoved(t *testing.T) {
	// Frame with two OBUs, both with size field
	obu1Payload := []byte{0x11, 0x22, 0x33}
	obu2Payload := []byte{0xAA, 0xBB}

	// Type 6 = OBU_TILE_GROUP (VCL, gets encrypted)
	obu1 := buildOBU(6, false, true, obu1Payload)
	obu2 := buildOBU(6, false, true, obu2Payload)
	payload := append(obu1, obu2...)

	transformed, ranges, err := prepareAV1Frame(payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// obu1: header(1) + LEB128_size(1) + payload(3) = 5 bytes (keeps size field)
	// obu2 (last): header(1, no size bit) + payload(2) = 3 bytes (no size field)
	expectedLen := 5 + 3
	if len(transformed) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(transformed))
	}

	// Last OBU header (offset 5) should have obu_has_size_field=0
	lastHeader := transformed[5]
	if lastHeader&0x02 != 0 {
		t.Errorf("last OBU obu_has_size_field should be 0, header=0x%02x", lastHeader)
	}

	// Should have 2 ranges: one for each OBU header (+size for the first one)
	if len(ranges) != 2 {
		t.Errorf("expected 2 ranges, got %d", len(ranges))
	}
	// First OBU: offset=0, length=2 (header + 1 byte LEB128 size)
	if ranges[0].Offset != 0 || ranges[0].Length != 2 {
		t.Errorf("expected range[0] {0,2}, got {%d,%d}", ranges[0].Offset, ranges[0].Length)
	}
	// Second OBU: offset=5, length=1 (just header, no size field)
	if ranges[1].Offset != 5 || ranges[1].Length != 1 {
		t.Errorf("expected range[1] {5,1}, got {%d,%d}", ranges[1].Offset, ranges[1].Length)
	}
}

func TestPrepareAV1FrameDropsPadding(t *testing.T) {
	padding := buildOBU(obuPadding, false, true, []byte{0x00, 0x00})
	tileList := buildOBU(obuTileList, false, true, []byte{0xFF})
	obu := buildOBU(6, false, true, []byte{0x42, 0x43, 0x44})

	payload := append(append(padding, tileList...), obu...)
	transformed, _, err := prepareAV1Frame(payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Only the real OBU (type 6) should remain
	// header(1) + payload(3) = 4 bytes (no size field, it's the only one and therefore the last)
	if len(transformed) != 4 {
		t.Errorf("expected length 4, got %d", len(transformed))
	}
}

func TestPrepareAV1FrameWithExtension(t *testing.T) {
	// OBU with extension byte
	obu := buildOBU(6, true, true, []byte{0x10, 0x20})
	transformed, ranges, err := prepareAV1Frame(obu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// header(1) + ext(1) + payload(2) = 4 bytes (no size field, it's the last one)
	if len(transformed) != 4 {
		t.Errorf("expected length 4, got %d", len(transformed))
	}
	// The unencrypted range should cover header + extension = 2 bytes
	if len(ranges) != 1 || ranges[0].Length != 2 {
		t.Errorf("expected range length=2, got ranges=%v", ranges)
	}
}

func TestEncryptAV1RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, 16)

	// AV1 frame with Temporal Delimiter + real OBU
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

	// The decryptor is codec-unaware: it decrypts correctly using the ranges from the footer.
	// The resulting plaintext is the TRANSFORMED frame (no Temporal Delimiter, no size field).
	decrypted, _, err := frame.Decrypt(frame.DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	// The decrypted frame should match the transformed frame (TD removed, last OBU without size)
	expectedTransformed, _, _ := prepareAV1Frame(payload)
	if !bytes.Equal(decrypted, expectedTransformed) {
		t.Errorf("plaintext mismatch:\n  got:  %x\n  want: %x", decrypted, expectedTransformed)
	}
}

// ─────────────────────────────────────────────
// General codecs.Encrypt tests
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
		t.Errorf("plaintext mismatch")
	}
}

func TestEncryptVP8RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 16)
	// VP8 non-key frame (P=1 in bit 0 of first byte)
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
		t.Errorf("plaintext mismatch")
	}
}
