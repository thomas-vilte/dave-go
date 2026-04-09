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

// Expand extiende el nonce truncado de 32 bits a un contador de 64 bits.
// Usa la misma idea que un extensor de secuencia RTP: elige el ciclo 2^32 más
// cercano al máximo observado para tolerar reordering chico y detectar wraparound.
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

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
