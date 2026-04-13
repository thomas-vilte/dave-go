package mediakeys

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestKeyRatchetDeterministic(t *testing.T) {
	base := bytes.Repeat([]byte{0x11}, 16)

	r1, err := NewKeyRatchet(base)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	r2, err := NewKeyRatchet(base)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	k1, err := r1.GetKey(7)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := r2.GetKey(7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("same base secret must derive same key")
	}
}

func TestKeyRatchetCachesPreviousGeneration(t *testing.T) {
	now := time.Unix(100, 0)
	r, err := NewKeyRatchet(
		bytes.Repeat([]byte{0x22}, 16),
		WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	k0, err := r.GetKey(0)
	if err != nil {
		t.Fatal(err)
	}
	k3, err := r.GetKey(3)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k0, k3) {
		t.Fatal("different generations must produce different keys")
	}
	k0Again, err := r.GetKey(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k0, k0Again) {
		t.Fatal("cached generation mismatch")
	}
}

func TestKeyRatchetExpiresOldGeneration(t *testing.T) {
	now := time.Unix(100, 0)
	r, err := NewKeyRatchet(
		bytes.Repeat([]byte{0x33}, 16),
		WithRetentionTTL(10*time.Second),
		WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	if _, err := r.GetKey(2); err != nil {
		t.Fatal(err)
	}

	now = now.Add(11 * time.Second)
	r.PruneExpired()

	if _, err := r.GetKey(0); !errors.Is(err, ErrGenerationExpired) {
		t.Fatalf("expected ErrGenerationExpired, got %v", err)
	}
}

func TestKeyRatchetInvalidBaseSecret(t *testing.T) {
	_, err := NewKeyRatchet([]byte{0x01})
	if !errors.Is(err, ErrInvalidBaseSecret) {
		t.Fatalf("expected ErrInvalidBaseSecret, got %v", err)
	}
}

func TestKeyRatchetCurrentGeneration(t *testing.T) {
	r, err := NewKeyRatchet(bytes.Repeat([]byte{0x44}, 16))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	if r.CurrentGeneration() != 0 {
		t.Fatalf("expected generation 0, got %d", r.CurrentGeneration())
	}
	if _, err := r.GetKey(5); err != nil {
		t.Fatal(err)
	}
	if r.CurrentGeneration() != 5 {
		t.Fatalf("expected generation 5, got %d", r.CurrentGeneration())
	}
}

func TestKeyRatchetMatchesDaveyVector(t *testing.T) {
	base := []byte{206, 221, 97, 177, 184, 161, 202, 105, 4, 101, 84, 40, 44, 247, 11, 123}
	r, err := NewKeyRatchet(base)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	got, err := r.GetKey(0)
	if err != nil {
		t.Fatalf("GetKey(0): %v", err)
	}

	want := []byte{117, 48, 249, 169, 148, 94, 45, 46, 6, 208, 101, 31, 123, 42, 134, 75}
	if !bytes.Equal(got, want) {
		t.Fatalf("generation 0 key mismatch:\n got  %v\n want %v", got, want)
	}
}
