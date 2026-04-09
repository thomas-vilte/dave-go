package mediakeys

import "testing"

func TestNonceCounterGenerations(t *testing.T) {
	c := NewNonceCounter()

	_, truncated, generation := c.Next()
	if truncated != 1 || generation != 0 {
		t.Fatalf("first counter mismatch: nonce=%d generation=%d", truncated, generation)
	}

	c.counter = 1<<24 - 1
	_, truncated, generation = c.Next()
	if truncated != 1<<24 || generation != 1 {
		t.Fatalf("boundary mismatch: nonce=%d generation=%d", truncated, generation)
	}

	_, truncated, generation = c.Next()
	if truncated != 1<<24+1 || generation != 1 {
		t.Fatalf("generation rollover mismatch: nonce=%d generation=%d", truncated, generation)
	}
}

func TestNonceCounterReset(t *testing.T) {
	c := NewNonceCounter()
	c.Next()
	c.Next()
	c.Reset()
	if c.Current() != 0 {
		t.Fatalf("expected counter 0 after reset, got %d", c.Current())
	}
}

func TestNonceExpanderWraparound(t *testing.T) {
	e := NewNonceExpander()

	if got := e.Expand(0xFFFFFFFE); got != 0xFFFFFFFE {
		t.Fatalf("unexpected first value: %d", got)
	}
	if got := e.Expand(0xFFFFFFFF); got != 0xFFFFFFFF {
		t.Fatalf("unexpected second value: %d", got)
	}
	if got := e.Expand(0); got != 1<<32 {
		t.Fatalf("wrap mismatch: got %d want %d", got, uint64(1<<32))
	}
}

func TestNonceExpanderOutOfOrder(t *testing.T) {
	e := NewNonceExpander()

	e.Expand(100)
	got := e.Expand(95)
	if got != 95 {
		t.Fatalf("out-of-order mismatch: got %d want 95", got)
	}
}

func TestGenerationFromTruncatedNonce(t *testing.T) {
	if g := GenerationFromTruncatedNonce(0x00000000); g != 0 {
		t.Fatalf("expected generation 0, got %d", g)
	}
	if g := GenerationFromTruncatedNonce(0x01000000); g != 1 {
		t.Fatalf("expected generation 1, got %d", g)
	}
	if g := GenerationFromTruncatedNonce(0xFF000000); g != 0xFF {
		t.Fatalf("expected generation 0xFF, got %d", g)
	}
}

func TestTruncatedNonceFromCounter(t *testing.T) {
	if n := TruncatedNonceFromCounter(0x0102030405060708); n != 0x05060708 {
		t.Fatalf("expected 0x05060708, got 0x%08x", n)
	}
}
