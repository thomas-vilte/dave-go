package frame

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"
)

func discordMLSReferenceEncryptSecureFrame(key []byte, nonce uint32, opusData []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	fullNonce := make([]byte, 12)
	binary.LittleEndian.PutUint32(fullNonce[8:], nonce)
	sealed := gcm.Seal(nil, fullNonce, opusData, nil)

	ciphertext := sealed[:len(opusData)]
	truncatedTag := sealed[len(opusData) : len(opusData)+8]
	nonceBytes := EncodeULEB128(nonce)
	supplementalSize := byte(8 + len(nonceBytes) + 1 + 2)

	result := make([]byte, 0, len(ciphertext)+8+len(nonceBytes)+3)
	result = append(result, ciphertext...)
	result = append(result, truncatedTag...)
	result = append(result, nonceBytes...)
	result = append(result, supplementalSize)
	result = append(result, 0xFA, 0xFA)
	return result
}

func TestEncodeDecodeULEB128(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
	}{
		{"zero", 0},
		{"one", 1},
		{"small", 42},
		{"max_byte", 127},
		{"two_bytes", 128},
		{"two_bytes_max", 16383},
		{"three_bytes", 16384},
		{"large", 1<<24 - 1},
		{"max_uint32", ^uint32(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeULEB128(tt.value)
			decoded, n, err := DecodeULEB128(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if decoded != tt.value {
				t.Errorf("got %d, want %d", decoded, tt.value)
			}
			if n != len(encoded) {
				t.Errorf("bytes read %d != encoded length %d", n, len(encoded))
			}
		})
	}
}

func TestDecodeULEB128Errors(t *testing.T) {
	_, _, err := DecodeULEB128(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}

	_, _, err = DecodeULEB128([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestValidateRanges(t *testing.T) {
	tests := []struct {
		name    string
		ranges  []Range
		size    int
		wantErr bool
	}{
		{"empty", nil, 100, false},
		{"single_valid", []Range{{0, 10}}, 100, false},
		{"two_valid", []Range{{0, 10}, {20, 10}}, 100, false},
		{"adjacent", []Range{{0, 10}, {10, 10}}, 100, false},
		{"overlapping", []Range{{0, 20}, {10, 10}}, 100, true},
		{"out_of_bounds", []Range{{90, 20}}, 100, true},
		{"negative_offset", []Range{{-1, 10}}, 100, true},
		{"negative_length", []Range{{0, -1}}, 100, true},
		{"unsorted", []Range{{20, 10}, {5, 10}}, 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRanges(tt.ranges, tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestContiguousPlaintextSize(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		ranges []Range
		want   int
	}{
		{"no_ranges", 100, nil, 100},
		{"one_range", 100, []Range{{0, 10}}, 90},
		{"two_ranges", 100, []Range{{0, 10}, {20, 5}}, 85},
		{"full_encrypted", 100, []Range{{0, 100}}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContiguousPlaintextSize(tt.size, tt.ranges)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExtractCiphertext(t *testing.T) {
	// Frame: "ABCDEFGH" con rangos unencrypted {0,2} y {4,2}
	// Bytes cifrados: posiciones 2-3 ("CD") y 6-7 ("GH")
	frame := []byte("ABCDEFGH")
	ranges := []Range{{0, 2}, {4, 2}}
	got := ExtractCiphertext(frame, ranges)
	want := []byte("CDGH")
	if !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReconstructPlaintext(t *testing.T) {
	// Real-world case: the interleaved frame has unencrypted bytes at their original
	// positions and ciphertext at the encrypted positions.
	//
	// Original: "ABCDEFGH" with unencrypted ranges {2,2} and {6,2}
	//   - Positions 2-3 ("CD") and 6-7 ("GH") stay unencrypted
	//   - Positions 0-1 ("AB") and 4-5 ("EF") get encrypted
	//
	// Interleaved: [cc,dd,C,D,gg,hh,G,H] (cc,dd,gg,hh = ciphertext; C,D,G,H = plaintext)
	// Decrypted:   [A,B,E,F] (plaintext decrypted from encrypted positions)
	// Result:      [A,B,C,D,E,F,G,H]
	interleaved := []byte{0xCC, 0xDD, 67, 68, 0xEE, 0xFF, 71, 72}
	decrypted := []byte{65, 66, 69, 70} // A,B,E,F
	ranges := []Range{{2, 2}, {6, 2}}
	got := ReconstructPlaintext(interleaved, decrypted, ranges)
	want := []byte("ABCDEFGH")
	if !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReconstructPlaintextFullEncrypt(t *testing.T) {
	// The whole frame was encrypted (no unencrypted ranges)
	interleaved := []byte("xxxxxxxx")
	decrypted := []byte("ABCDEFGH")
	got := ReconstructPlaintext(interleaved, decrypted, nil)
	want := []byte("ABCDEFGH")
	if !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLooksLikeDAVEFrame(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{"too_short", []byte{0xFA, 0xFA}, false},
		{"no_magic", []byte("hello world"), false},
		{"valid_minimal", append(append([]byte("hello world"), 0x01, 0x02), 0xFA, 0xFA), true},
		{"magic_at_wrong_pos", []byte("hello\xFA\xFAworld"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeDAVEFrame(tt.packet)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name   string
		data   []byte
		nonce  uint32
		ranges []Range
	}{
		{"empty", []byte{}, 0, nil},
		{"small", []byte("hello"), 1, nil},
		{"with_ranges", []byte("ABCDEFGH"), 42, []Range{{0, 2}, {4, 2}}},
		{"large", bytes.Repeat([]byte("x"), 1000), 999, nil},
		{"full_encrypted", []byte("test"), 0, []Range{{0, 4}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(EncryptParams{
				Plaintext:         tt.data,
				Key:               key,
				TruncatedNonce:    tt.nonce,
				UnencryptedRanges: tt.ranges,
			})
			if err != nil {
				t.Fatalf("encrypt error: %v", err)
			}

			decrypted, nonce, err := Decrypt(DecryptParams{
				Ciphertext: encrypted,
				Key:        key,
			})
			if err != nil {
				t.Fatalf("decrypt error: %v", err)
			}

			if nonce != tt.nonce {
				t.Errorf("nonce: got %d, want %d", nonce, tt.nonce)
			}

			if !bytes.Equal(decrypted, tt.data) {
				t.Errorf("data mismatch:\n  got:  %v\n  want: %v", decrypted, tt.data)
			}
		})
	}
}

func TestEncryptProducesMagicMarker(t *testing.T) {
	key := make([]byte, 16)
	data := []byte("test data")
	encrypted, err := Encrypt(EncryptParams{
		Plaintext: data,
		Key:       key,
	})
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	if !LooksLikeDAVEFrame(encrypted) {
		t.Error("encrypted frame should have magic marker")
	}
}

func TestEncryptInvalidKey(t *testing.T) {
	_, err := Encrypt(EncryptParams{
		Plaintext: []byte("test"),
		Key:       []byte("short"),
	})
	if !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("got err=%v, want %v", err, ErrInvalidKeyLength)
	}
}

func TestEncryptInvalidRanges(t *testing.T) {
	key := make([]byte, 16)
	_, err := Encrypt(EncryptParams{
		Plaintext:         []byte("test"),
		Key:               key,
		UnencryptedRanges: []Range{{10, 5}},
	})
	if !errors.Is(err, ErrInvalidRanges) {
		t.Errorf("got err=%v, want %v", err, ErrInvalidRanges)
	}
}

func TestDecryptInvalidFrame(t *testing.T) {
	key := make([]byte, 16)
	_, _, err := Decrypt(DecryptParams{
		Ciphertext: []byte("no magic here"),
		Key:        key,
	})
	if err == nil {
		t.Error("expected error for non-DAVE frame")
	}
}

func TestDecryptTamperedFrame(t *testing.T) {
	key := make([]byte, 16)
	encrypted, err := Encrypt(EncryptParams{
		Plaintext: []byte("secret data"),
		Key:       key,
	})
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	// Tamper with the authentication tag (last 8 bytes of the footer, before the nonce)
	// The tag is at position len(encrypted) - 3(suppl+magic) - len(nonce) - 8
	// To keep it simple, we tamper the first byte of the interleaved frame which is ciphertext
	// (no unencrypted ranges, so the whole interleaved frame is ciphertext)
	encrypted[0] ^= 0xFF
	_, _, err = Decrypt(DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err == nil {
		t.Error("expected auth failure for tampered frame")
	}
}

func TestParseValidFrame(t *testing.T) {
	key := make([]byte, 16)
	nonce := uint32(12345)
	data := []byte("test payload")
	ranges := []Range{{0, 4}}

	encrypted, err := Encrypt(EncryptParams{
		Plaintext:         data,
		Key:               key,
		TruncatedNonce:    nonce,
		UnencryptedRanges: ranges,
	})
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	parsed, err := Parse(encrypted)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if parsed.TruncatedNonce != nonce {
		t.Errorf("nonce: got %d, want %d", parsed.TruncatedNonce, nonce)
	}

	if len(parsed.UnencryptedRanges) != len(ranges) {
		t.Errorf("ranges count: got %d, want %d", len(parsed.UnencryptedRanges), len(ranges))
	}

	if len(parsed.Tag) != 8 {
		t.Errorf("tag length: got %d, want 8", len(parsed.Tag))
	}
}

func TestParseTooShort(t *testing.T) {
	_, err := Parse([]byte{0xFA, 0xFA})
	if err == nil {
		t.Error("expected error for too short packet")
	}
}

func TestParseInvalidMagic(t *testing.T) {
	_, err := Parse([]byte("hello world"))
	if !errors.Is(err, ErrInvalidMagicMarker) {
		t.Errorf("got err=%v, want %v", err, ErrInvalidMagicMarker)
	}
}

func TestGCM8SealOpen(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}

	gcm, err := newGCM8(key)
	if err != nil {
		t.Fatalf("newGCM8 error: %v", err)
	}

	if gcm.NonceSize() != 12 {
		t.Errorf("nonce size: got %d, want 12", gcm.NonceSize())
	}
	if gcm.Overhead() != 8 {
		t.Errorf("overhead: got %d, want 8", gcm.Overhead())
	}

	nonce := make([]byte, 12)
	plaintext := []byte("hello world")
	aad := []byte("additional data")

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	if len(ciphertext) != len(plaintext)+8 {
		t.Errorf("ciphertext length: got %d, want %d", len(ciphertext), len(plaintext)+8)
	}

	decrypted, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("open error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %v, want %v", decrypted, plaintext)
	}
}

func TestGCM8WrongAAD(t *testing.T) {
	key := make([]byte, 16)
	gcm, _ := newGCM8(key)

	nonce := make([]byte, 12)
	plaintext := []byte("secret")
	aad := []byte("correct aad")

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	_, err := gcm.Open(nil, nonce, ciphertext, []byte("wrong aad"))
	if err == nil {
		t.Error("expected auth failure with wrong AAD")
	}
}

func TestGCM8WrongNonce(t *testing.T) {
	key := make([]byte, 16)
	gcm, _ := newGCM8(key)

	nonce := make([]byte, 12)
	plaintext := []byte("secret")

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	wrongNonce := make([]byte, 12)
	wrongNonce[0] = 1
	_, err := gcm.Open(nil, wrongNonce, ciphertext, nil)
	if err == nil {
		t.Error("expected auth failure with wrong nonce")
	}
}

func TestGCM8TamperedCiphertext(t *testing.T) {
	key := make([]byte, 16)
	gcm, _ := newGCM8(key)

	nonce := make([]byte, 12)
	plaintext := []byte("secret message")

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext[0] ^= 0xFF
	_, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err == nil {
		t.Error("expected auth failure for tampered ciphertext")
	}
}

func TestGCM8TamperedTag(t *testing.T) {
	key := make([]byte, 16)
	gcm, _ := newGCM8(key)

	nonce := make([]byte, 12)
	plaintext := []byte("secret")

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext[len(ciphertext)-1] ^= 0xFF
	_, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err == nil {
		t.Error("expected auth failure for tampered tag")
	}
}

func TestNonceExpansion(t *testing.T) {
	tests := []struct {
		nonce uint32
		want  []byte
	}{
		{0, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{1, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{0x01020304, []byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
		{0xFFFFFFFF, []byte{0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255}},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			var nonce [12]byte
			binary.BigEndian.PutUint32(nonce[8:], tt.nonce)
			if !bytes.Equal(nonce[:], tt.want) {
				t.Errorf("got %v, want %v", nonce[:], tt.want)
			}
		})
	}
}

func TestEncryptDecryptWithVP8Ranges(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	vp8NonKey := []byte{0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	vp8Key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

	tests := []struct {
		name   string
		data   []byte
		ranges []Range
	}{
		{"vp8_non_key", vp8NonKey, []Range{{0, 1}}},
		{"vp8_key", vp8Key, []Range{{0, 10}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(EncryptParams{
				Plaintext:         tt.data,
				Key:               key,
				TruncatedNonce:    1,
				UnencryptedRanges: tt.ranges,
			})
			if err != nil {
				t.Fatalf("encrypt error: %v", err)
			}

			decrypted, _, err := Decrypt(DecryptParams{
				Ciphertext: encrypted,
				Key:        key,
			})
			if err != nil {
				t.Fatalf("decrypt error: %v", err)
			}

			if !bytes.Equal(decrypted, tt.data) {
				t.Errorf("data mismatch: got %v, want %v", decrypted, tt.data)
			}
		})
	}
}

func TestDifferentNonceDifferentCiphertext(t *testing.T) {
	key := make([]byte, 16)
	data := []byte("same plaintext")

	enc1, _ := Encrypt(EncryptParams{
		Plaintext:      data,
		Key:            key,
		TruncatedNonce: 1,
	})
	enc2, _ := Encrypt(EncryptParams{
		Plaintext:      data,
		Key:            key,
		TruncatedNonce: 2,
	})

	if bytes.Equal(enc1, enc2) {
		t.Error("different nonces should produce different ciphertexts")
	}
}

func TestEncryptOpusMatchesDiscordMLSReference(t *testing.T) {
	key := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	opus := []byte{0xf8, 0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04}
	nonce := uint32(0x01020304)

	got, err := Encrypt(EncryptParams{
		Plaintext:      opus,
		Key:            key,
		TruncatedNonce: nonce,
	})
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	want := discordMLSReferenceEncryptSecureFrame(key, nonce, opus)
	if !bytes.Equal(got, want) {
		t.Fatalf("Opus frame mismatch with discordmls reference:\n got  %x\n want %x", got, want)
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key := make([]byte, 16)
	encrypted, err := Encrypt(EncryptParams{
		Plaintext:      []byte{},
		Key:            key,
		TruncatedNonce: 0,
	})
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	decrypted, _, err := Decrypt(DecryptParams{
		Ciphertext: encrypted,
		Key:        key,
	})
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestParseSupplementalSize(t *testing.T) {
	key := make([]byte, 16)
	encrypted, err := Encrypt(EncryptParams{
		Plaintext:      []byte("test"),
		Key:            key,
		TruncatedNonce: 0,
	})
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	parsed, err := Parse(encrypted)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if parsed.SupplementalSize == 0 {
		t.Error("supplemental size should not be zero")
	}
}
