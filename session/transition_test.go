package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/mediakeys"
)

// makeTestRatchet builds a real KeyRatchet with a known base secret so
// Encrypt can call GetKey without panicking on a nil secret.
func makeTestRatchet(t *testing.T) *mediakeys.KeyRatchet {
	t.Helper()
	r, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	return r
}

// newTransitionTestSession sets up a session with an active epoch and a
// real send ratchet so Encrypt can encrypt. sendRetentionTTL is short so
// the transition-expiry tests don't take 10s.
func newTransitionTestSession(t *testing.T) *Session {
	t.Helper()
	s := New("123456789", testCallbacks{})
	s.SetChannelID(42)
	s.AssignSsrcToCodec(1, godave.CodecOpus)
	s.sendRetentionTTL = 50 * time.Millisecond

	ratchet := makeTestRatchet(t)
	s.mu.Lock()
	s.activeEpoch = &epochState{
		id:      1,
		senders: map[godave.UserID]*senderState{s.userID: {ratchet: ratchet}},
	}
	s.sendRatchet = ratchet
	s.mu.Unlock()

	return s
}

// TestEncrypt_UsesRetainedDuringTransitionWindow verifies that after
// activatePendingEpochLocked swaps in a new send ratchet, Encrypt keeps
// using the OLD one (via retainedSendRatchet) instead of the new one, and
// TransitionFrames is incremented.
func TestEncrypt_UsesRetainedDuringTransitionWindow(t *testing.T) {
	s := newTransitionTestSession(t)

	oldRatchet := s.sendRatchet
	oldCounterValue := s.sendCounter.Current()

	// Simulate a new epoch activating: build a new activeEpoch and a new
	// sendRatchet, and stash the OLD into retained (this is what
	// activatePendingEpochLocked does after the fix).
	newRatchet := makeTestRatchet(t)
	s.mu.Lock()
	s.activeEpoch = &epochState{
		id:      2,
		senders: map[godave.UserID]*senderState{s.userID: {ratchet: newRatchet}},
	}
	s.retainedSendRatchet = oldRatchet
	s.retainedSendExpiresAt = time.Now().Add(s.sendRetentionTTL)
	s.sendRatchet = newRatchet
	s.mu.Unlock()

	plaintext := []byte{0x10, 0x20, 0x30}
	out := make([]byte, 64)
	if _, err := s.Encrypt(1, plaintext, out); err != nil {
		t.Fatalf("Encrypt during transition: %v", err)
	}

	// Counter must have continued from the OLD value (no reset yet).
	if got := s.sendCounter.Current(); got <= oldCounterValue {
		t.Fatalf("expected counter to advance past %d, got %d", oldCounterValue, got)
	}

	if got := s.Stats().TransitionFrames; got != 1 {
		t.Fatalf("TransitionFrames = %d, want 1", got)
	}

	// The retained must still be set (not yet expired).
	if s.retainedSendRatchet == nil {
		t.Fatal("retainedSendRatchet cleared before TTL elapsed")
	}
}

// TestEncrypt_SwitchesToNewAfterRetainedExpires verifies that once the
// retained ratchet expires, selectSendRatchetLocked resets the counter
// (so the new ratchet starts from nonce 0 per spec) and Encrypt uses the
// new ratchet. TransitionFrames stops incrementing.
func TestEncrypt_SwitchesToNewAfterRetainedExpires(t *testing.T) {
	s := newTransitionTestSession(t)

	oldRatchet := s.sendRatchet
	newRatchet := makeTestRatchet(t)
	s.mu.Lock()
	s.activeEpoch = &epochState{
		id:      2,
		senders: map[godave.UserID]*senderState{s.userID: {ratchet: newRatchet}},
	}
	s.retainedSendRatchet = oldRatchet
	s.retainedSendExpiresAt = time.Now().Add(s.sendRetentionTTL)
	s.sendRatchet = newRatchet
	s.mu.Unlock()

	// Sleep past the TTL.
	time.Sleep(2 * s.sendRetentionTTL)

	plaintext := []byte{0x10, 0x20, 0x30}
	out := make([]byte, 64)
	if _, err := s.Encrypt(1, plaintext, out); err != nil {
		t.Fatalf("Encrypt after expiry: %v", err)
	}

	// After expiry, the retained is cleared and counter reset to 0, then
	// incremented to 1 by the first Encrypt.
	if s.retainedSendRatchet != nil {
		t.Fatal("retainedSendRatchet not cleared after expiry")
	}
	if !s.retainedSendExpiresAt.IsZero() {
		t.Fatalf("retainedSendExpiresAt = %v, want zero", s.retainedSendExpiresAt)
	}
	if got := s.sendCounter.Current(); got != 1 {
		t.Fatalf("counter = %d after expiry+Encrypt, want 1 (reset then +1)", got)
	}
	if got := s.Stats().TransitionFrames; got != 0 {
		t.Fatalf("TransitionFrames = %d after expiry, want 0", got)
	}
}

// TestEncrypt_UsesRetainedAfterProtocolReset verifies that when
// OnSelectProtocolAck clears sendRatchet, the OLD one is stashed in
// retained and Encrypt uses it during the transition window before the
// new epoch activates.
func TestEncrypt_UsesRetainedAfterProtocolReset(t *testing.T) {
	s := newTransitionTestSession(t)
	oldRatchet := s.sendRatchet

	s.OnSelectProtocolAck(1)

	plaintext := []byte{0x10, 0x20, 0x30}
	out := make([]byte, 64)
	if _, err := s.Encrypt(1, plaintext, out); err != nil {
		t.Fatalf("Encrypt after protocol reset: %v", err)
	}

	if s.retainedSendRatchet == nil {
		t.Fatal("retainedSendRatchet nil after OnSelectProtocolAck")
	}
	if s.retainedSendRatchet != oldRatchet {
		t.Fatal("retainedSendRatchet does not point to the OLD sendRatchet")
	}
	if s.sendRatchet != nil {
		t.Fatal("sendRatchet should be nil after OnSelectProtocolAck")
	}
	if got := s.Stats().TransitionFrames; got != 1 {
		t.Fatalf("TransitionFrames = %d, want 1", got)
	}
}

// TestEncrypt_FallsToPassthroughIfNoRetainedAndNoRatchet is a regression
// test for the fresh-session passthrough path: with neither retained nor
// sendRatchet, Encrypt must not panic and must passthrough.
func TestEncrypt_FallsToPassthroughIfNoRetainedAndNoRatchet(t *testing.T) {
	s := New("123456789", testCallbacks{})

	plaintext := []byte{0x10, 0x20, 0x30}
	out := make([]byte, 64)
	n, err := s.Encrypt(1, plaintext, out)
	if err != nil {
		t.Fatalf("Encrypt with no ratchet: %v", err)
	}
	if n != len(plaintext) {
		t.Fatalf("passthrough wrote %d, want %d", n, len(plaintext))
	}
	if !bytes.Equal(out[:n], plaintext) {
		t.Fatalf("passthrough altered the frame")
	}
	if got := s.Stats().TransitionFrames; got != 0 {
		t.Fatalf("TransitionFrames = %d, want 0", got)
	}
}

// TestEncrypt_NoDoubleCounterReset verifies the counter is reset exactly
// once during a transition: not at activation, only when the retained
// ratchet expires.
func TestEncrypt_NoDoubleCounterReset(t *testing.T) {
	s := newTransitionTestSession(t)

	oldRatchet := s.sendRatchet
	// Push the counter forward so we can detect any spurious reset.
	s.mu.Lock()
	for range 5 {
		_, _, _ = s.sendCounter.Next()
	}
	counterBeforeTransition := s.sendCounter.Current()
	s.activeEpoch = &epochState{
		id:      2,
		senders: map[godave.UserID]*senderState{s.userID: {ratchet: makeTestRatchet(t)}},
	}
	s.retainedSendRatchet = oldRatchet
	s.retainedSendExpiresAt = time.Now().Add(s.sendRetentionTTL)
	s.sendRatchet = makeTestRatchet(t)
	s.mu.Unlock()

	// One Encrypt during the transition window. Counter must advance by 1
	// (no reset).
	plaintext := []byte{0xAA}
	out := make([]byte, 64)
	if _, err := s.Encrypt(1, plaintext, out); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := s.sendCounter.Current(); got != counterBeforeTransition+1 {
		t.Fatalf("counter = %d after transition Encrypt, want %d (no reset)", got, counterBeforeTransition+1)
	}

	// Wait for the retained to expire, then Encrypt. Counter should reset
	// to 0 then advance to 1.
	time.Sleep(2 * s.sendRetentionTTL)
	if _, err := s.Encrypt(1, plaintext, out); err != nil {
		t.Fatalf("Encrypt after expiry: %v", err)
	}
	if got := s.sendCounter.Current(); got != 1 {
		t.Fatalf("counter = %d after post-expiry Encrypt, want 1", got)
	}
}
