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

type cachedGeneration struct {
	key       []byte
	expiresAt time.Time
}

type KeyRatchet struct {
	mu sync.Mutex

	retentionTTL time.Duration
	now          func() time.Time

	secret     *ciphersuite.Secret
	generation uint32
	cache      map[uint32]cachedGeneration
}

func NewKeyRatchet(baseSecret []byte, opts ...Option) (*KeyRatchet, error) {
	if len(baseSecret) != BaseSecretLen {
		return nil, ErrInvalidBaseSecret
	}

	r := &KeyRatchet{
		retentionTTL: DefaultRetentionTTL,
		now:          time.Now,
		secret:       ciphersuite.NewSecret(baseSecret),
		cache:        make(map[uint32]cachedGeneration),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r, nil
}

func (r *KeyRatchet) CurrentGeneration() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generation
}

func (r *KeyRatchet) GetKey(target uint32) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpiredLocked()
	if target < r.generation {
		cached, ok := r.cache[target]
		if !ok {
			return nil, ErrGenerationExpired
		}
		out := make([]byte, len(cached.key))
		copy(out, cached.key)
		return out, nil
	}
	for r.generation < target {
		currentKey, err := deriveKeyForGeneration(r.secret, r.generation)
		if err != nil {
			return nil, err
		}
		r.cache[r.generation] = cachedGeneration{
			key:       currentKey,
			expiresAt: r.now().Add(r.retentionTTL),
		}
		nextSecret, err := advanceSecret(r.secret, r.generation)
		if err != nil {
			return nil, err
		}
		r.secret.SecureZero()
		r.secret = nextSecret
		r.generation++
	}
	key, err := deriveKeyForGeneration(r.secret, target)
	if err != nil {
		return nil, err
	}
	return key, nil
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
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
