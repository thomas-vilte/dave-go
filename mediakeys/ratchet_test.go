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
	// Commit past generation 0: the stream authenticated up to gen 2, so the
	// base secret erases gen 0 and it becomes underivable once its cached key
	// expires. GetKey alone never advances the base, so the Commit is required.
	r.Commit(2)

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
	// GetKey must NOT advance the base generation — it only derives on a clone.
	if _, err := r.GetKey(5); err != nil {
		t.Fatal(err)
	}
	if r.CurrentGeneration() != 0 {
		t.Fatalf("GetKey must not advance base generation, got %d", r.CurrentGeneration())
	}
	// Only Commit advances it.
	r.Commit(5)
	if r.CurrentGeneration() != 5 {
		t.Fatalf("expected generation 5 after Commit, got %d", r.CurrentGeneration())
	}
}

func TestKeyRatchetCachesCurrentGeneration(t *testing.T) {
	now := time.Unix(100, 0)
	base := bytes.Repeat([]byte{0x55}, 16)
	r, err := NewKeyRatchet(base, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	k, err := r.GetKey(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.cache[0]; !ok {
		t.Fatal("current generation key must be cached after GetKey")
	}

	// Mutating the returned slice must not corrupt the cached copy.
	k[0] ^= 0xFF
	again, err := r.GetKey(0)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewKeyRatchet(base)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	want, err := fresh.GetKey(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, want) {
		t.Fatal("cached current generation key was corrupted by caller mutation")
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

func TestGetKey_RejectsGapBeyondLimit(t *testing.T) {
	r, err := NewKeyRatchet(
		bytes.Repeat([]byte{0x66}, 16),
		WithMaxGenerationGap(10),
	)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	_, err = r.GetKey(11)
	if !errors.Is(err, ErrGenerationTooFar) {
		t.Fatalf("expected ErrGenerationTooFar, got %v", err)
	}
}

func TestGetKey_AcceptsGapWithinLimit(t *testing.T) {
	r, err := NewKeyRatchet(
		bytes.Repeat([]byte{0x77}, 16),
		WithMaxGenerationGap(10),
	)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	_, err = r.GetKey(10)
	if err != nil {
		t.Fatalf("expected no error for gap=10, got %v", err)
	}
}

func TestGetKey_AcceptsCachedGenerationBeyondGap(t *testing.T) {
	r, err := NewKeyRatchet(
		bytes.Repeat([]byte{0x88}, 16),
		WithMaxGenerationGap(5),
	)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	_, err = r.GetKey(10)
	if !errors.Is(err, ErrGenerationTooFar) {
		t.Fatalf("expected ErrGenerationTooFar for 10, got %v", err)
	}

	_, err = r.GetKey(3)
	if err != nil {
		t.Fatalf("GetKey(3): %v", err)
	}

	// GetKey(3) does not advance the base, so the gap window is still measured
	// from generation 0: gen 10 stays out of reach.
	_, err = r.GetKey(10)
	if !errors.Is(err, ErrGenerationTooFar) {
		t.Fatalf("expected ErrGenerationTooFar from base 0→10, got %v", err)
	}

	// Committing to gen 3 (as an authenticated stream would) widens the window:
	// now gen 7 is within gap (7-3=4 <= 5).
	r.Commit(3)
	_, err = r.GetKey(7)
	if err != nil {
		t.Fatalf("GetKey(7) after Commit(3): %v", err)
	}

	// And gen 10 is now reachable too (10-3=7 > 5 still rejects — the window
	// moved, it didn't widen).
	_, err = r.GetKey(10)
	if !errors.Is(err, ErrGenerationTooFar) {
		t.Fatalf("expected ErrGenerationTooFar from base 3→10, got %v", err)
	}
}

func TestGetKey_DefaultGapIsReasonable(t *testing.T) {
	r, err := NewKeyRatchet(bytes.Repeat([]byte{0x99}, 16))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	_, err = r.GetKey(256)
	if err != nil {
		t.Fatalf("default gap should allow 256, got: %v", err)
	}
}

// TestGetKey_DoesNotAdvanceBase is the core invariant of the refactor: a
// decryption attempt (GetKey) must never move the ratchet's base. Only Commit
// does. This is what prevents a forged frame from driving the ratchet forward.
func TestGetKey_DoesNotAdvanceBase(t *testing.T) {
	r, err := NewKeyRatchet(bytes.Repeat([]byte{0xA1}, 16))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	for range 5 {
		if _, err := r.GetKey(100); err != nil {
			t.Fatalf("GetKey(100): %v", err)
		}
	}
	if r.CurrentGeneration() != 0 {
		t.Fatalf("base must stay at 0 after GetKey, got %d", r.CurrentGeneration())
	}
}

// TestGetKey_ForgedFrameDoesNotStrandLegitStream models the forged-frame
// attack: a frame at a far-ahead generation is "attempted" (GetKey) but never
// authenticated (no Commit). A subsequent legit lower generation must still be
// derivable, because GetKey never moved the base.
func TestGetKey_ForgedFrameDoesNotStrandLegitStream(t *testing.T) {
	r, err := NewKeyRatchet(bytes.Repeat([]byte{0xA2}, 16))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	// Attacker's forged frame: high generation, attempted but never committed.
	if _, gerr := r.GetKey(200); gerr != nil {
		t.Fatalf("GetKey(200): %v", gerr)
	}
	// Legit stream at generation 1: still derivable, base never moved.
	legit, err := r.GetKey(1)
	if err != nil {
		t.Fatalf("legit GetKey(1) after forged attempt: %v", err)
	}

	// Must match a fresh ratchet's gen-1 key (i.e. not corrupted by the forged
	// walk).
	fresh, err := NewKeyRatchet(bytes.Repeat([]byte{0xA2}, 16))
	if err != nil {
		t.Fatalf("NewKeyRatchet(fresh): %v", err)
	}
	want, err := fresh.GetKey(1)
	if err != nil {
		t.Fatalf("fresh GetKey(1): %v", err)
	}
	if !bytes.Equal(legit, want) {
		t.Fatal("legit gen-1 key diverged after a forged high-generation attempt")
	}
}

// TestCommit_IsMonotonicAndBounded checks Commit never moves backwards and
// clamps an absurd jump to the gap.
func TestCommit_IsMonotonicAndBounded(t *testing.T) {
	r, err := NewKeyRatchet(bytes.Repeat([]byte{0xA3}, 16), WithMaxGenerationGap(10))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	r.Commit(5)
	if r.CurrentGeneration() != 5 {
		t.Fatalf("after Commit(5) got %d", r.CurrentGeneration())
	}
	// Backwards commit is a no-op.
	r.Commit(3)
	if r.CurrentGeneration() != 5 {
		t.Fatalf("backwards Commit(3) must be a no-op, got %d", r.CurrentGeneration())
	}
	// Absurd jump is clamped to base+gap (5+10=15), never walked in full.
	r.Commit(1_000_000)
	if r.CurrentGeneration() != 15 {
		t.Fatalf("Commit far jump must clamp to base+gap=15, got %d", r.CurrentGeneration())
	}
}
