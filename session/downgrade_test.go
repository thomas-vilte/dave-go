package session

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/mediakeys"
)

// downgradeCallbacks tracks SendReadyForTransition calls during downgrade tests.
type downgradeCallbacks struct {
	mu               sync.Mutex
	readyTransitions []uint16
	keyPackages      int
	invalidCommits   int
}

func (c *downgradeCallbacks) SendMLSKeyPackage([]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages++

	return nil
}
func (c *downgradeCallbacks) SendMLSCommitWelcome([]byte) error { return nil }
func (c *downgradeCallbacks) SendReadyForTransition(transitionID uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readyTransitions = append(c.readyTransitions, transitionID)

	return nil
}

func (c *downgradeCallbacks) SendInvalidCommitWelcome(transitionID uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidCommits++

	return nil
}

func (c *downgradeCallbacks) readyTransitionIDs() []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint16, len(c.readyTransitions))
	copy(out, c.readyTransitions)

	return out
}

// newDowngradeTestSession creates a session with an active epoch and send ratchet
// so the downgrade can clear it. sendRetentionTTL is short for test speed.
func newDowngradeTestSession(t *testing.T) (*session, *downgradeCallbacks) {
	t.Helper()
	cb := &downgradeCallbacks{}
	s := newSession(nil, "123456789", cb)
	s.SetChannelID(42)
	s.AssignSsrcToCodec(1, godave.CodecOpus)
	s.sendRetentionTTL = 50 * time.Millisecond

	ratchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	s.mu.Lock()
	s.protocolVersion = 1
	s.activeEpoch = &epochState{
		id:      1,
		senders: map[godave.UserID]*senderState{s.userID: {ratchet: ratchet}},
	}
	s.sendRatchet = ratchet
	s.mu.Unlock()

	return s, cb
}

// TestDowngradeV0_PrepareSendsReadyForTransition verifies that
// OnDavePrepareTransition with protocolVersion=0 sends ready_for_transition
// immediately, because no commit/welcome will arrive for a downgrade.
func TestDowngradeV0_PrepareSendsReadyForTransition(t *testing.T) {
	s, cb := newDowngradeTestSession(t)

	s.OnDavePrepareTransition(7, 0)

	ids := cb.readyTransitionIDs()
	if len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("expected ready_for_transition(7), got %v", ids)
	}
}

// TestDowngradeV0_ExecuteClearsSendSide verifies that after
// OnDavePrepareTransition + OnDaveExecuteTransition to v0, the send-side
// is cleared and Encrypt falls back to passthrough.
func TestDowngradeV0_ExecuteClearsSendSide(t *testing.T) {
	s, _ := newDowngradeTestSession(t)

	// Prepare the downgrade.
	s.OnDavePrepareTransition(3, 0)

	// Execute the downgrade.
	s.OnDaveExecuteTransition(3)

	// Send-side must be cleared.
	s.mu.RLock()
	if s.sendRatchet != nil {
		t.Error("sendRatchet should be nil after v0 execute")
	}
	if s.retainedSendRatchet != nil {
		t.Error("retainedSendRatchet should be nil after v0 execute")
	}
	if s.sendCipher != nil {
		t.Error("sendCipher should be nil after v0 execute")
	}
	s.mu.RUnlock()

	// Encrypt must fall back to passthrough.
	plaintext := []byte{0x10, 0x20, 0x30}
	out := make([]byte, 64)
	n, err := s.Encrypt(1, plaintext, out)
	if err != nil {
		t.Fatalf("Encrypt after v0 downgrade: %v", err)
	}
	if !bytes.Equal(out[:n], plaintext) {
		t.Fatalf("Encrypt should passthrough after v0 downgrade, got %x", out[:n])
	}
	if got := s.Stats().PassthroughFrames; got != 1 {
		t.Fatalf("PassthroughFrames = %d, want 1", got)
	}
}

// TestDowngradeV0_ExecuteRetainsEpochForReceive verifies that activeEpoch
// is NOT cleared during a v0 downgrade — it's kept for receive-side
// retention of in-flight DAVE frames (protocol.md:129).
func TestDowngradeV0_ExecuteRetainsEpochForReceive(t *testing.T) {
	s, _ := newDowngradeTestSession(t)

	s.OnDavePrepareTransition(5, 0)
	s.OnDaveExecuteTransition(5)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeEpoch == nil {
		t.Fatal("activeEpoch should NOT be nil after v0 execute (needed for receive retention)")
	}
	if s.activeEpoch.id != 1 {
		t.Fatalf("activeEpoch.id = %d, want 1", s.activeEpoch.id)
	}
}

// TestDowngradeV0_ReceivePassesThroughV0Frames verifies that after a downgrade
// to transport-only, non-DAVE (v0 plaintext) frames pass through Decrypt even
// though activeEpoch is still retained. Without protocolVersion awareness, the
// E2EE passthrough guard would wrongly reject these frames (protocol.md:129).
func TestDowngradeV0_ReceivePassesThroughV0Frames(t *testing.T) {
	s, _ := newDowngradeTestSession(t)

	s.OnDavePrepareTransition(8, 0)
	s.OnDaveExecuteTransition(8)

	// activeEpoch is retained but the session is now transport-only.
	v0Frame := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	out := make([]byte, 64)
	n, err := s.Decrypt("someuser", v0Frame, out)
	if err != nil {
		t.Fatalf("v0 frame must pass through after downgrade, got: %v", err)
	}
	if !bytes.Equal(out[:n], v0Frame) {
		t.Fatalf("passthrough altered the frame: got %x want %x", out[:n], v0Frame)
	}
}

// TestDowngradeV0_ExecuteClearsPendingEpoch verifies that any stale
// pendingEpoch is cleared during a v0 downgrade.
func TestDowngradeV0_ExecuteClearsPendingEpoch(t *testing.T) {
	s, _ := newDowngradeTestSession(t)

	// Inject a stale pendingEpoch (simulates a concurrent upgrade that
	// was interrupted by the downgrade).
	s.mu.Lock()
	s.pendingEpoch = &epochState{
		id:      99,
		senders: map[godave.UserID]*senderState{s.userID: {ratchet: s.sendRatchet}},
	}
	s.pendingGroupID = []byte{0xDE, 0xAD}
	s.mu.Unlock()

	s.OnDavePrepareTransition(4, 0)
	s.OnDaveExecuteTransition(4)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pendingEpoch != nil {
		t.Error("pendingEpoch should be nil after v0 execute")
	}
	if s.pendingGroupID != nil {
		t.Error("pendingGroupID should be nil after v0 execute")
	}
}

// TestDowngradeV0_StatsIncrement verifies that DowngradeToV0 is incremented.
func TestDowngradeV0_StatsIncrement(t *testing.T) {
	s, _ := newDowngradeTestSession(t)

	s.OnDavePrepareTransition(1, 0)
	s.OnDaveExecuteTransition(1)

	if got := s.Stats().DowngradeToV0; got != 1 {
		t.Fatalf("DowngradeToV0 = %d, want 1", got)
	}
}

// TestUpgrade_NoDowngradeBehavior verifies that OnDavePrepareTransition with
// protocolVersion > 0 does NOT send ready_for_transition (the commit/welcome
// flow handles it).
func TestUpgrade_NoDowngradeBehavior(t *testing.T) {
	s, cb := newDowngradeTestSession(t)

	s.OnDavePrepareTransition(10, 1)

	ids := cb.readyTransitionIDs()
	if len(ids) != 0 {
		t.Fatalf("expected no ready_for_transition for upgrade, got %v", ids)
	}
}

// TestDowngradeV0_ExecuteClearsGroupID verifies that groupID is cleared
// during a v0 downgrade so the session returns to a clean state.
func TestDowngradeV0_ExecuteClearsGroupID(t *testing.T) {
	s, _ := newDowngradeTestSession(t)

	s.mu.Lock()
	s.groupID = []byte{0x01, 0x02, 0x03}
	s.mu.Unlock()

	s.OnDavePrepareTransition(6, 0)
	s.OnDaveExecuteTransition(6)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.groupID != nil {
		t.Errorf("groupID should be nil after v0 downgrade, got %x", s.groupID)
	}
}
