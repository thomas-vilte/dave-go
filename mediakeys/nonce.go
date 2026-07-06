package mediakeys

func GenerationFromTruncatedNonce(nonce uint32) uint32 {
	return nonce >> 24
}

func TruncatedNonceFromCounter(counter uint64) uint32 {
	return uint32(counter)
}

type NonceCounter struct {
	counter uint64
}

func NewNonceCounter() *NonceCounter {
	return &NonceCounter{}
}

func (c *NonceCounter) Current() uint64 {
	return c.counter
}

func (c *NonceCounter) Next() (full uint64, truncated uint32, generation uint32) {
	c.counter++
	full = c.counter
	truncated = uint32(full)
	generation = uint32(full >> 24)

	return full, truncated, generation
}

func (c *NonceCounter) Reset() {
	c.counter = 0
}

type NonceExpander struct {
	initialized bool
	highestSeen uint64
}

func NewNonceExpander() *NonceExpander {
	return &NonceExpander{}
}

// Expand extends the truncated 32-bit nonce to a 64-bit counter.
// Uses the same idea as an RTP sequence number extender: picks the 2^32 cycle
// closest to the highest seen value to tolerate small reordering and detect wraparound.
func (e *NonceExpander) Expand(truncated uint32) uint64 {
	if !e.initialized {
		full := uint64(truncated)
		e.initialized = true
		e.highestSeen = full

		return full
	}

	baseCycle := e.highestSeen >> 32
	best := (baseCycle << 32) | uint64(truncated)
	bestDist := absDiff(best, e.highestSeen)

	if baseCycle > 0 {
		candidate := ((baseCycle - 1) << 32) | uint64(truncated)
		if d := absDiff(candidate, e.highestSeen); d < bestDist {
			best = candidate
			bestDist = d
		}
	}

	candidate := ((baseCycle + 1) << 32) | uint64(truncated)
	if d := absDiff(candidate, e.highestSeen); d < bestDist {
		best = candidate
	}
	if best > e.highestSeen {
		e.highestSeen = best
	}

	return best
}

// ExpandTentative returns the expanded nonce candidate without mutating state.
// Use Commit after successful frame authentication to apply the advance.
// This prevents forged frames from poisoning the expander state.
func (e *NonceExpander) ExpandTentative(truncated uint32) uint64 {
	if !e.initialized {
		return uint64(truncated)
	}

	baseCycle := e.highestSeen >> 32
	best := (baseCycle << 32) | uint64(truncated)
	bestDist := absDiff(best, e.highestSeen)

	if baseCycle > 0 {
		candidate := ((baseCycle - 1) << 32) | uint64(truncated)
		if d := absDiff(candidate, e.highestSeen); d < bestDist {
			best = candidate
			bestDist = d
		}
	}

	candidate := ((baseCycle + 1) << 32) | uint64(truncated)
	if d := absDiff(candidate, e.highestSeen); d < bestDist {
		best = candidate
	}

	return best
}

// Commit applies the nonce expansion that ExpandTentative computed.
// Must be called only after the frame carrying this nonce has been
// authenticated (GCM tag verified). Advances highestSeen if nonce is new.
func (e *NonceExpander) Commit(nonce uint64) {
	if !e.initialized {
		e.initialized = true
		e.highestSeen = nonce

		return
	}
	if nonce > e.highestSeen {
		e.highestSeen = nonce
	}
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}

	return b - a
}
