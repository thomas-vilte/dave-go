package session

import "testing"

func TestAntiReplay_FirstNonceAccepted(t *testing.T) {
	var w antiReplayWindow
	if !w.checkAndMark(10) {
		t.Fatal("first nonce must be accepted")
	}
	if w.highest != 10 || w.bitmap != 1 {
		t.Fatalf("state mismatch: highest=%d bitmap=%d", w.highest, w.bitmap)
	}
}

func TestAntiReplay_ExactReplayRejected(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(42)
	if w.checkAndMark(42) {
		t.Fatal("exact replay must be rejected")
	}
}

func TestAntiReplay_HigherNonceAccepted(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(10)
	if !w.checkAndMark(15) {
		t.Fatal("higher nonce must be accepted")
	}
	if w.highest != 15 {
		t.Fatalf("highest should be 15, got %d", w.highest)
	}
	// Bit 0 (15) and bit 5 (10) must be set.
	if w.bitmap&1 == 0 || w.bitmap&(1<<5) == 0 {
		t.Fatalf("bitmap missing bits: %064b", w.bitmap)
	}
}

func TestAntiReplay_LowerNonceWithinWindowRejected(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(10)
	w.checkAndMark(15)
	// 10 was already seen (bit 5 relative to highest=15).
	if w.checkAndMark(10) {
		t.Fatal("lower nonce already seen must be rejected")
	}
}

func TestAntiReplay_LowerNonceWithinWindowNotSeenAccepted(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(10)
	w.checkAndMark(15)
	// 12 was never seen.
	if !w.checkAndMark(12) {
		t.Fatal("lower nonce never seen within window must be accepted")
	}
	if w.highest != 15 {
		t.Fatalf("highest must not change: got %d", w.highest)
	}
}

func TestAntiReplay_OutsideWindowAccepted(t *testing.T) {
	var w antiReplayWindow
	// Fill window: nonces 64..127 (highest=127).
	for i := uint64(64); i <= 127; i++ {
		w.checkAndMark(i)
	}
	// Nonce 0 is 127 positions back — outside the 64-nonce window.
	// Must be accepted (key expiration protects old frames).
	if !w.checkAndMark(0) {
		t.Fatal("nonce outside window must be accepted")
	}
}

func TestAntiReplay_WindowFullRejected(t *testing.T) {
	var w antiReplayWindow
	// Fill window: nonces 0..63 (highest=63).
	for i := uint64(0); i <= 63; i++ {
		w.checkAndMark(i)
	}
	// Nonce 0 is within the window (delta=63 < 64) and already seen.
	if w.checkAndMark(0) {
		t.Fatal("nonce within window already seen must be rejected")
	}
}

func TestAntiReplay_ResetClearsState(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(100)
	w.reset()
	if w.seen {
		t.Fatal("reset must clear seen flag")
	}
	// After reset, nonce 100 must be accepted again.
	if !w.checkAndMark(100) {
		t.Fatal("nonce must be accepted after reset")
	}
}

func TestAntiReplay_ExactReplaySameNonce(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(50)
	// Exact replay of nonce 50.
	if w.checkAndMark(50) {
		t.Fatal("replay of same nonce must be rejected")
	}
}

func TestAntiReplay_OutOfOrderWithinWindow(t *testing.T) {
	var w antiReplayWindow
	// Accept 10, 15, 8 (out of order).
	w.checkAndMark(10)
	w.checkAndMark(15)
	if !w.checkAndMark(8) {
		t.Fatal("out-of-order within window must be accepted")
	}
	// Now replay 8 — must be rejected.
	if w.checkAndMark(8) {
		t.Fatal("replay of 8 must be rejected after it was accepted")
	}
}
