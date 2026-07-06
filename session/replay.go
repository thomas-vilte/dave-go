package session

import "fmt"

// antiReplayWindow implements an SRTP-style sliding window anti-replay check.
// It tracks the highest nonce seen and a bitmap of the last 64 nonces
// relative to it. Frames with nonces within the window that have already
// been seen are rejected. Frames outside the window (older than 64 nonces
// below highest) are accepted — they're protected by key expiration.
//
// NOT safe for concurrent use. The caller (session.Decrypt) must
// synchronize externally.
type antiReplayWindow struct {
	highest uint64
	bitmap  uint64
	seen    bool
}

// checkAndMark records nonce and returns true if it's new (not a replay).
// Returns false if the nonce was already seen (replay detected).
func (w *antiReplayWindow) checkAndMark(nonce uint64) bool {
	if !w.seen {
		w.highest = nonce
		w.bitmap = 1
		w.seen = true

		return true
	}

	if nonce == w.highest {
		return false
	}

	if nonce > w.highest {
		shift := nonce - w.highest
		if shift < 64 {
			w.bitmap <<= shift
		} else {
			w.bitmap = 0
		}
		w.bitmap |= 1 // mark new highest
		w.highest = nonce

		return true
	}

	// nonce < w.highest
	delta := w.highest - nonce
	if delta >= 64 {
		return true // outside window, accept (protect by key expiration)
	}

	bit := uint64(1) << delta
	if w.bitmap&bit != 0 {
		return false // already seen
	}
	w.bitmap |= bit

	return true
}

// reset clears the anti-replay window state.
func (w *antiReplayWindow) reset() {
	w.highest = 0
	w.bitmap = 0
	w.seen = false
}

func (w *antiReplayWindow) String() string {
	return fmt.Sprintf("antiReplayWindow{highest=%d, seen=%v, bitmap=%064b}",
		w.highest, w.seen, w.bitmap)
}
