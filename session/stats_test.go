package session

import (
	"errors"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/mediakeys"
)

// TestStats_DecryptFailuresCounted covers the Decrypt error paths that must
// increment Stats.DecryptFailures: plaintext injected under active E2EE and a
// DAVE-looking frame no epoch/sender can decrypt. Clean passthrough (no E2EE)
// must NOT count.
func TestStats_DecryptFailuresCounted(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	buf := make([]byte, 64)

	// No active epoch: clean passthrough, must not count.
	if _, err := s.Decrypt("user1", []byte{0x01, 0x02, 0x03}, buf); err != nil {
		t.Fatalf("passthrough decrypt: %v", err)
	}
	if got := s.Stats().DecryptFailures; got != 0 {
		t.Fatalf("DecryptFailures after passthrough = %d, want 0", got)
	}

	// Active epoch + protocol v1: a non-DAVE frame is a plaintext injection.
	s.mu.Lock()
	s.activeEpoch = &epochState{id: 1, groupID: []byte("g"), senders: map[godave.UserID]*senderState{}}
	s.protocolVersion = 1
	s.mu.Unlock()
	if _, err := s.Decrypt("user1", []byte{0x01, 0x02, 0x03}, buf); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("plaintext under E2EE: err = %v, want ErrDecryptionFailed", err)
	}
	if got := s.Stats().DecryptFailures; got != 1 {
		t.Fatalf("DecryptFailures after injection = %d, want 1", got)
	}

	// DAVE-looking frame (magic marker, >=11 bytes) with no known sender.
	daveish := append(make([]byte, 12), 0xFA, 0xFA)
	if _, err := s.Decrypt("user1", daveish, buf); err == nil {
		t.Fatal("DAVE-looking frame with no known sender should fail")
	}
	if got := s.Stats().DecryptFailures; got != 2 {
		t.Fatalf("DecryptFailures after unknown-sender frame = %d, want 2", got)
	}
}

// TestStats_TransitionWindowsIncremented covers that entering the retention
// window (activating a new epoch while a previous sendRatchet is set)
// increments TransitionWindows, without touching TransitionFrames.
func TestStats_TransitionWindowsIncremented(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	s.sendRetentionTTL = 50 * time.Millisecond

	// Simulate an "old" ratchet that gets retained when the new epoch activates.
	oldRatchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	newRatchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet (new): %v", err)
	}

	s.mu.Lock()
	s.sendRatchet = oldRatchet
	// A same-membership transition (re-key) — the only case that retains the
	// send ratchet. A join would skip retention (the new member holds no
	// old-epoch keys); see newEpochAddsSender.
	s.activeEpoch = &epochState{
		id:      6,
		senders: map[godave.UserID]*senderState{"123456789": {ratchet: oldRatchet}},
	}
	s.pendingEpoch = &epochState{
		id:      7,
		groupID: []byte("g"),
		senders: map[godave.UserID]*senderState{"123456789": {ratchet: newRatchet}},
	}
	s.mu.Unlock()

	// Activate. Must: (a) retain oldRatchet, (b) increment TransitionWindows.
	s.mu.Lock()
	s.activatePendingEpochLocked()
	got := s.stats.TransitionWindows
	s.mu.Unlock()
	if got != 1 {
		t.Fatalf("TransitionWindows = %d after first activate, want 1", got)
	}
	if s.retainedSendRatchet != oldRatchet {
		t.Fatalf("retainedSendRatchet not set to oldRatchet")
	}

	// Wait for the retention to expire. selectSendRatchetLocked must reset it.
	time.Sleep(80 * time.Millisecond)
	s.mu.RLock()
	_ = s.selectSendRatchetLocked()
	s.mu.RUnlock()

	// Activate again with a fresh ratchet: must enter another window.
	secondRatchet, _ := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	s.mu.Lock()
	s.sendRatchet = secondRatchet
	s.pendingEpoch = &epochState{
		id:      8,
		groupID: []byte("g2"),
		senders: map[godave.UserID]*senderState{"123456789": {ratchet: newRatchet}},
	}
	s.mu.Unlock()

	s.mu.Lock()
	s.activatePendingEpochLocked()
	got = s.stats.TransitionWindows
	s.mu.Unlock()
	if got != 2 {
		t.Fatalf("TransitionWindows = %d after second activate, want 2", got)
	}
}

// TestStats_DegradedDurationAccumulated covers that DegradedDuration
// accumulates the total time between markDegradedLocked and
// markRecoveredLocked across multiple cycles.
func TestStats_DegradedDurationAccumulated(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

	s.mu.Lock()
	s.markDegradedLocked("test reason")
	s.mu.Unlock()

	// Wait a delta and recover.
	const sleep = 30 * time.Millisecond
	time.Sleep(sleep)

	s.mu.Lock()
	s.markRecoveredLocked(1)
	dur1 := s.stats.DegradedDuration
	s.mu.Unlock()

	if dur1 < sleep {
		t.Fatalf("DegradedDuration = %v after first recovery, want >= %v", dur1, sleep)
	}

	// Second cycle: must accumulate (not reset).
	s.mu.Lock()
	s.markDegradedLocked("another reason")
	s.mu.Unlock()
	time.Sleep(sleep)
	s.mu.Lock()
	s.markRecoveredLocked(2)
	dur2 := s.stats.DegradedDuration
	s.mu.Unlock()

	if dur2 < 2*sleep {
		t.Fatalf("DegradedDuration = %v after second recovery, want >= %v (accumulated)", dur2, 2*sleep)
	}
	if dur2 < dur1+sleep/2 {
		t.Fatalf("dur2=%v did not accumulate over dur1=%v", dur2, dur1)
	}
}

// TestStats_RecoveryAttemptsNotTransportOnMLSFault verifies that
// RecoveryAttemptsTransport does not move when the recovery isn't caused by
// a "shard is not ready" transport failure. A plain markDegradedLocked +
// markRecoveredLocked cycle (no invalidateAndResendKeyPackageLocked involved)
// must leave the transport counter untouched.
func TestStats_RecoveryAttemptsNotTransportOnMLSFault(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	s.recoveryTimeout = 5 * time.Millisecond

	s.mu.Lock()
	beforeTransport := s.stats.RecoveryAttemptsTransport
	s.mu.Unlock()

	s.mu.Lock()
	s.markDegradedLocked("mls fault simulated")
	s.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	s.mu.Lock()
	s.markRecoveredLocked(3)
	afterTransport := s.stats.RecoveryAttemptsTransport
	s.mu.Unlock()

	if beforeTransport != afterTransport {
		t.Fatalf("RecoveryAttemptsTransport changed from %d to %d without a real isShardNotReady failure",
			beforeTransport, afterTransport)
	}
}

// TestStats_RecoveryAttemptsTransportIncrementsOnShardNotReady covers the
// real scenario RecoveryAttemptsTransport exists for: invalidateAndResendKeyPackageLocked
// bails out on a transport failure (shardNotReadyCallbacks, shared with
// recovery_test.go) instead of arming the watchdog. Complements
// TestInvalidation_NoWatchdogOnShardNotReady (which checks the watchdog does
// NOT fire) by asserting the counter that lets an integrator observe this
// happened at all.
func TestStats_RecoveryAttemptsTransportIncrementsOnShardNotReady(t *testing.T) {
	cb := &shardNotReadyCallbacks{}
	s := newRecoveryTestSession(t, cb)

	s.mu.Lock()
	before := s.stats.RecoveryAttemptsTransport
	s.invalidateAndResendKeyPackageLocked()
	after := s.stats.RecoveryAttemptsTransport
	s.mu.Unlock()

	if after != before+1 {
		t.Fatalf("RecoveryAttemptsTransport = %d after shard-not-ready invalidation, want %d", after, before+1)
	}

	// The MLS-fault counter must stay untouched: this was a transport skip,
	// not an armed recovery watchdog.
	s.mu.Lock()
	mlsAttempts := s.stats.RecoveryAttempts
	s.mu.Unlock()
	if mlsAttempts != 0 {
		t.Fatalf("RecoveryAttempts = %d, want 0 (this path never arms the MLS watchdog)", mlsAttempts)
	}
}
