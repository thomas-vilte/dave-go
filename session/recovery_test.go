package session

import (
	"sync"
	"testing"
	"time"

	"github.com/disgoorg/godave"
)

// countingCallbacks counts gateway sends so tests can observe the recovery
// watchdog retrying and giving up.
type countingCallbacks struct {
	mu             sync.Mutex
	invalidCommits int
	keyPackages    int
}

func (c *countingCallbacks) SendMLSKeyPackage([]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages++

	return nil
}
func (c *countingCallbacks) SendMLSCommitWelcome([]byte) error   { return nil }
func (c *countingCallbacks) SendReadyForTransition(uint16) error { return nil }
func (c *countingCallbacks) SendInvalidCommitWelcome(uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidCommits++

	return nil
}

func (c *countingCallbacks) counts() (invalidCommits, keyPackages int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.invalidCommits, c.keyPackages
}

func newRecoveryTestSession(t *testing.T, cb godave.Callbacks) *session {
	t.Helper()
	s := New(nil, "123456789", cb).(*session)
	s.recoveryTimeout = 10 * time.Millisecond
	// The session only generates key packages after the gateway selected the
	// DAVE protocol version.
	s.OnSelectProtocolAck(1)

	return s
}

// eventually polls cond until it holds or the deadline expires.
func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestRecoveryWatchdogRetriesThenGivesUp(t *testing.T) {
	cb := &countingCallbacks{}
	s := newRecoveryTestSession(t, cb)

	s.mu.Lock()
	s.invalidateAndResendKeyPackageLocked()
	s.mu.Unlock()

	// Each timed-out attempt re-signals InvalidCommitWelcome and re-invalidates;
	// after maxRecoveryAttempts the watchdog must stop re-arming.
	eventually(t, func() bool {
		invalid, _ := cb.counts()

		return invalid == maxRecoveryAttempts
	}, "watchdog never exhausted its recovery attempts")

	time.Sleep(5 * s.recoveryTimeout)
	invalid, _ := cb.counts()
	if invalid != maxRecoveryAttempts {
		t.Fatalf("watchdog kept retrying after giving up: %d invalid commits, want %d", invalid, maxRecoveryAttempts)
	}
}

func TestRecoveryWatchdogStopsWhenEpochActivates(t *testing.T) {
	cb := &countingCallbacks{}
	s := newRecoveryTestSession(t, cb)

	s.mu.Lock()
	s.invalidateAndResendKeyPackageLocked()
	// Simulate the epoch activating right after the invalidation.
	s.recoveryAttempts = 0
	s.signalEpochReadyLocked()
	s.mu.Unlock()

	time.Sleep(5 * s.recoveryTimeout)
	invalid, _ := cb.counts()
	if invalid != 0 {
		t.Fatalf("watchdog fired despite epoch activation: %d invalid commits", invalid)
	}
}
