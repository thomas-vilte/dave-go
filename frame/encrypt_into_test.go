package frame

import (
	"bytes"
	"testing"
)

func TestEncryptIntoMatchesEncrypt(t *testing.T) {
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
		{"opus_no_ranges", []byte("opus frame payload"), 7, nil},
		{"empty", []byte{}, 0, nil},
		{"with_ranges", []byte("ABCDEFGH"), 42, []Range{{0, 2}, {4, 2}}},
		{"large_nonce", bytes.Repeat([]byte("x"), 200), 1<<32 - 1, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := Encrypt(EncryptParams{
				Plaintext:         tt.data,
				Key:               key,
				TruncatedNonce:    tt.nonce,
				UnencryptedRanges: tt.ranges,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			dst := make([]byte, len(tt.data)+64)
			n, err := EncryptInto(dst, EncryptParams{
				Plaintext:         tt.data,
				Key:               key,
				TruncatedNonce:    tt.nonce,
				UnencryptedRanges: tt.ranges,
			})
			if err != nil {
				t.Fatalf("EncryptInto: %v", err)
			}
			if !bytes.Equal(dst[:n], want) {
				t.Errorf("EncryptInto result mismatch:\n  got:  %x\n  want: %x", dst[:n], want)
			}

			decrypted, nonce, err := Decrypt(DecryptParams{Ciphertext: dst[:n], Key: key})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if nonce != tt.nonce {
				t.Errorf("nonce: got %d, want %d", nonce, tt.nonce)
			}
			if !bytes.Equal(decrypted, tt.data) {
				t.Errorf("decrypted mismatch:\n  got:  %v\n  want: %v", decrypted, tt.data)
			}
		})
	}
}

func TestEncryptWithCipherIntoMatchesEncryptWithCipher(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	gcm, err := newGCM8(key)
	if err != nil {
		t.Fatalf("newGCM8: %v", err)
	}

	plaintext := []byte("opus frame payload")
	want, err := EncryptWithCipher(EncryptWithCipherParams{
		Plaintext:      plaintext,
		Cipher:         gcm,
		TruncatedNonce: 7,
	})
	if err != nil {
		t.Fatalf("EncryptWithCipher: %v", err)
	}

	dst := make([]byte, len(plaintext)+64)
	n, err := EncryptWithCipherInto(dst, EncryptWithCipherParams{
		Plaintext:      plaintext,
		Cipher:         gcm,
		TruncatedNonce: 7,
	})
	if err != nil {
		t.Fatalf("EncryptWithCipherInto: %v", err)
	}
	if !bytes.Equal(dst[:n], want) {
		t.Errorf("EncryptWithCipherInto result mismatch:\n  got:  %x\n  want: %x", dst[:n], want)
	}
}

func TestEncryptIntoBufferTooSmall(t *testing.T) {
	key := make([]byte, 16)
	plaintext := []byte("opus frame payload")

	dst := make([]byte, 4)
	_, err := EncryptInto(dst, EncryptParams{
		Plaintext:      plaintext,
		Key:            key,
		TruncatedNonce: 0,
	})
	if err == nil {
		t.Fatal("expected error for undersized buffer")
	}
}

func TestEncryptIntoNoRangesAllocs(t *testing.T) {
	key := make([]byte, 16)
	gcm, err := newGCM8(key)
	if err != nil {
		t.Fatalf("newGCM8: %v", err)
	}
	plaintext := bytes.Repeat([]byte("x"), 160)
	dst := make([]byte, len(plaintext)+64)

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := EncryptWithCipherInto(dst, EncryptWithCipherParams{
			Plaintext:      plaintext,
			Cipher:         gcm,
			TruncatedNonce: 1,
		}); err != nil {
			t.Fatalf("EncryptWithCipherInto: %v", err)
		}
	})
	if allocs > 1 {
		t.Errorf("EncryptWithCipherInto: got %v allocs/op, want <= 1", allocs)
	}
}

func BenchmarkEncryptWithCipher(b *testing.B) {
	key := make([]byte, 16)
	gcm, err := newGCM8(key)
	if err != nil {
		b.Fatalf("newGCM8: %v", err)
	}
	plaintext := bytes.Repeat([]byte("x"), 160)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithCipher(EncryptWithCipherParams{
			Plaintext:      plaintext,
			Cipher:         gcm,
			TruncatedNonce: uint32(i),
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptWithCipherInto(b *testing.B) {
	key := make([]byte, 16)
	gcm, err := newGCM8(key)
	if err != nil {
		b.Fatalf("newGCM8: %v", err)
	}
	plaintext := bytes.Repeat([]byte("x"), 160)
	dst := make([]byte, len(plaintext)+64)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithCipherInto(dst, EncryptWithCipherParams{
			Plaintext:      plaintext,
			Cipher:         gcm,
			TruncatedNonce: uint32(i),
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptWithCipherWithRanges(b *testing.B) {
	key := make([]byte, 16)
	gcm, err := newGCM8(key)
	if err != nil {
		b.Fatalf("newGCM8: %v", err)
	}
	plaintext := bytes.Repeat([]byte("x"), 160)
	ranges := []Range{{Offset: 0, Length: 4}, {Offset: 20, Length: 4}}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithCipher(EncryptWithCipherParams{
			Plaintext:         plaintext,
			Cipher:            gcm,
			TruncatedNonce:    uint32(i),
			UnencryptedRanges: ranges,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptWithCipherIntoWithRanges(b *testing.B) {
	key := make([]byte, 16)
	gcm, err := newGCM8(key)
	if err != nil {
		b.Fatalf("newGCM8: %v", err)
	}
	plaintext := bytes.Repeat([]byte("x"), 160)
	ranges := []Range{{Offset: 0, Length: 4}, {Offset: 20, Length: 4}}
	dst := make([]byte, len(plaintext)+64)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithCipherInto(dst, EncryptWithCipherParams{
			Plaintext:         plaintext,
			Cipher:            gcm,
			TruncatedNonce:    uint32(i),
			UnencryptedRanges: ranges,
		}); err != nil {
			b.Fatal(err)
		}
	}
}
