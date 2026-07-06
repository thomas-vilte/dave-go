package mediakeys

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

type Option func(*KeyRatchet)

func WithRetentionTTL(ttl time.Duration) Option {
	return func(r *KeyRatchet) {
		r.retentionTTL = ttl
	}
}

func WithClock(now func() time.Time) Option {
	return func(r *KeyRatchet) {
		r.now = now
	}
}

func WithMaxGenerationGap(gap uint32) Option {
	return func(r *KeyRatchet) {
		r.maxGenerationGap = gap
	}
}

type cachedGeneration struct {
	key       []byte
	expiresAt time.Time
}

type KeyRatchet struct {
	mu sync.Mutex

	retentionTTL     time.Duration
	maxGenerationGap uint32
	now              func() time.Time

	// baseSecret is the ratchet secret at baseGeneration. It advances (and
	// erases the previous secret) ONLY via Commit — never as a side effect of
	// GetKey. A GetKey call is a decryption attempt that may be for a not-yet-
	// authenticated (possibly forged) frame, so it must not move the ratchet.
	baseSecret     *ciphersuite.Secret
	baseGeneration uint32
	cache          map[uint32]cachedGeneration
}

func NewKeyRatchet(baseSecret []byte, opts ...Option) (*KeyRatchet, error) {
	if len(baseSecret) != BaseSecretLen {
		return nil, ErrInvalidBaseSecret
	}

	r := &KeyRatchet{
		retentionTTL:     DefaultRetentionTTL,
		maxGenerationGap: DefaultMaxGenerationGap,
		now:              time.Now,
		baseSecret:       ciphersuite.NewSecret(baseSecret),
		cache:            make(map[uint32]cachedGeneration),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r, nil
}

// CurrentGeneration returns the ratchet's committed base generation — the
// lowest generation still derivable from baseSecret. It advances via Commit,
// not GetKey.
func (r *KeyRatchet) CurrentGeneration() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.baseGeneration
}

// GetKey returns the media key for target generation. It NEVER mutates the
// ratchet's base secret: it derives on a clone and memoizes the result in the
// cache. This makes a decryption attempt side-effect-free, so a forged frame
// (whose generation comes from an unauthenticated nonce) cannot drive the
// ratchet forward or strand the legitimate stream. The base only moves when
// the caller Commits a generation it trusts (own send counter, or a receive
// generation whose frame passed authentication).
func (r *KeyRatchet) GetKey(target uint32) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpiredLocked()

	// Hot path: the same generation is requested for up to 2^24 frames, so a
	// cache hit avoids re-deriving on every packet.
	if cached, ok := r.cache[target]; ok {
		return cloneKey(cached.key), nil
	}
	// The base advanced past target (via Commit) and target's key is no longer
	// cached: it has been erased per the retention window.
	if target < r.baseGeneration {
		return nil, ErrGenerationExpired
	}
	// Bound the forward walk relative to the last committed generation, so a
	// forged frame can neither drive the ratchet far ahead nor force unbounded
	// HKDF work (CPU DoS guard).
	if target-r.baseGeneration > r.maxGenerationGap {
		return nil, ErrGenerationTooFar
	}

	// Walk a clone forward from the base secret. Intermediate generation keys
	// are cached too, so out-of-order frames in [baseGeneration, target) don't
	// each trigger a fresh walk.
	work := r.baseSecret.Clone()
	for g := r.baseGeneration; g < target; g++ {
		if _, ok := r.cache[g]; !ok {
			k, err := deriveKeyForGeneration(work, g)
			if err != nil {
				work.SecureZero()

				return nil, err
			}
			r.cache[g] = cachedGeneration{key: k, expiresAt: r.now().Add(r.retentionTTL)}
		}
		next, err := advanceSecret(work, g)
		if err != nil {
			work.SecureZero()

			return nil, err
		}
		work.SecureZero()
		work = next
	}
	key, err := deriveKeyForGeneration(work, target)
	work.SecureZero()
	if err != nil {
		return nil, err
	}
	r.cache[target] = cachedGeneration{key: key, expiresAt: r.now().Add(r.retentionTTL)}

	return cloneKey(key), nil
}

// Commit advances the ratchet's base secret up to generation, erasing the
// secrets for older generations (forward hygiene). Call it ONLY for a
// generation the caller trusts: the local send counter (own frames) or a
// receive generation whose frame has passed AES-GCM authentication. This — not
// GetKey — is what moves the ratchet forward, so an unauthenticated frame can
// never push the base past the real stream position. Older generation keys
// remain available via the cache until their retention TTL elapses.
func (r *KeyRatchet) Commit(generation uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation <= r.baseGeneration {
		return
	}
	// A trusted stream advances one generation at a time, so a jump larger than
	// the gap can only be a bogus value — clamp the walk rather than do heavy
	// work on it.
	if generation-r.baseGeneration > r.maxGenerationGap {
		generation = r.baseGeneration + r.maxGenerationGap
	}
	for g := r.baseGeneration; g < generation; g++ {
		next, err := advanceSecret(r.baseSecret, g)
		if err != nil {
			return
		}
		r.baseSecret.SecureZero()
		r.baseSecret = next
	}
	r.baseGeneration = generation
}

func (r *KeyRatchet) PruneExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpiredLocked()
}

func (r *KeyRatchet) pruneExpiredLocked() {
	now := r.now()
	for generation, cached := range r.cache {
		if !cached.expiresAt.After(now) {
			zeroBytes(cached.key)
			delete(r.cache, generation)
		}
	}
}

func deriveKeyForGeneration(secret *ciphersuite.Secret, generation uint32) ([]byte, error) {
	context := make([]byte, 4)
	binary.BigEndian.PutUint32(context, generation)

	// DAVE uses derive_tree_secret(secret, "key", generation, 16), which internally
	// serializes generation as a big-endian uint32 within the KDF context.
	key, err := secret.KdfExpandLabel("key", context, MediaKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive generation key %d: %w", generation, err)
	}

	return key.AsSlice(), nil
}

func advanceSecret(secret *ciphersuite.Secret, generation uint32) (*ciphersuite.Secret, error) {
	context := make([]byte, 4)
	binary.BigEndian.PutUint32(context, generation)

	// DAVE advances the ratchet with derive_tree_secret(secret, "secret", generation, 32).
	// The inner secret grows to hash length (SHA-256 => 32 bytes), it doesn't stay at 16.
	next, err := secret.KdfExpandLabel("secret", context, 32)
	if err != nil {
		return nil, fmt.Errorf("advance generation %d: %w", generation, err)
	}

	return next, nil
}

func cloneKey(key []byte) []byte {
	out := make([]byte, len(key))
	copy(out, key)

	return out
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
