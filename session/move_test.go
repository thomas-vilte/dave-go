package session

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/mediakeys"
	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

type kpCapturingCallbacks struct {
	mu          sync.Mutex
	keyPackages [][]byte
}

func (c *kpCapturingCallbacks) SendMLSKeyPackage(kp []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages = append(c.keyPackages, append([]byte(nil), kp...))

	return nil
}
func (c *kpCapturingCallbacks) SendMLSCommitWelcome([]byte) error     { return nil }
func (c *kpCapturingCallbacks) SendReadyForTransition(uint16) error   { return nil }
func (c *kpCapturingCallbacks) SendInvalidCommitWelcome(uint16) error { return nil }

func (c *kpCapturingCallbacks) lastKeyPackage() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keyPackages) == 0 {
		return nil
	}

	return c.keyPackages[len(c.keyPackages)-1]
}

// TestOnSelectProtocolAck_DiscardsPreviousChannelState verifies that
// select_protocol_ack (sent by Discord whenever the bot joins/moves to a
// voice channel) fully discards an established session's MLS/epoch state and
// starts the new connection from scratch, with a fresh MLS client and key
// package.
func TestOnSelectProtocolAck_DiscardsPreviousChannelState(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New(nil, "123456789", cb).(*session)

	// Initial connection to channel A.
	s.OnSelectProtocolAck(1)
	kpA := cb.lastKeyPackage()
	if len(kpA) == 0 {
		t.Fatal("expected a key package to be sent on first protocol ack")
	}

	// Seed state as if channel A had an established, active DAVE session.
	ratchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	s.mu.Lock()
	clientA := s.mlsClient
	s.groupID = []byte("group-A")
	s.pendingGroupID = []byte("pending-group-A")
	s.activeEpoch = &epochState{id: 5, groupID: []byte("group-A"), senders: map[godave.UserID]*senderState{
		"123456789": {ratchet: ratchet},
	}}
	s.pendingEpoch = &epochState{id: 6, groupID: []byte("pending-group-A")}
	s.retainedEpoch = []*epochState{{id: 4}}
	s.proposalQueue = [][]byte{{0x01, 0x02}}
	s.pendingCommitBytes = []byte{0xAA}
	s.preCommitGroupState = []byte{0xBB}
	s.sendRatchet = ratchet
	s.mu.Unlock()

	// The bot is moved to channel B: Discord sends a fresh select_protocol_ack.
	s.OnSelectProtocolAck(1)
	kpB := cb.lastKeyPackage()

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.groupID != nil {
		t.Errorf("groupID not cleared: %x", s.groupID)
	}
	if s.pendingGroupID != nil {
		t.Errorf("pendingGroupID not cleared: %x", s.pendingGroupID)
	}
	if s.activeEpoch != nil {
		t.Errorf("activeEpoch not cleared: %+v", s.activeEpoch)
	}
	if s.pendingEpoch != nil {
		t.Errorf("pendingEpoch not cleared: %+v", s.pendingEpoch)
	}
	if len(s.retainedEpoch) != 0 {
		t.Errorf("retainedEpoch not cleared: %+v", s.retainedEpoch)
	}
	if len(s.proposalQueue) != 0 {
		t.Errorf("proposalQueue not cleared: %+v", s.proposalQueue)
	}
	if s.pendingCommitBytes != nil {
		t.Errorf("pendingCommitBytes not cleared: %x", s.pendingCommitBytes)
	}
	if s.preCommitGroupState != nil {
		t.Errorf("preCommitGroupState not cleared: %x", s.preCommitGroupState)
	}
	if s.sendRatchet != nil {
		t.Error("sendRatchet not cleared")
	}
	if s.mlsClient == nil {
		t.Fatal("expected a fresh mlsClient after move")
	}
	if s.mlsClient == clientA {
		t.Error("expected mlsClient to be replaced after move, got the same instance")
	}
	if len(kpB) == 0 {
		t.Fatal("expected a new key package to be sent after move")
	}
	if bytes.Equal(kpA, kpB) {
		t.Error("expected a different key package after move, got the same one")
	}
}

// TestSessionMove_StaleProposalIgnored_AndNewChannelJoinsCleanly simulates the
// known DAVE reproduction: the bot joins a voice channel (channel A), gets
// moved to a different channel (channel B), and a stale MLS proposal batch
// for the now-discarded channel A group arrives late. The stale message must
// be ignored without corrupting state, and the bot must still be able to join
// channel B's group from a clean slate.
func TestSessionMove_StaleProposalIgnored_AndNewChannelJoinsCleanly(t *testing.T) {
	ctx := context.Background()
	cb := &kpCapturingCallbacks{}
	s := New(nil, "123456789", cb).(*session)

	peerStore := memorystore.NewStore()
	peerIdentity, err := userIDToIdentityBytes("987654321")
	if err != nil {
		t.Fatalf("userIDToIdentityBytes: %v", err)
	}
	peer, err := mls.NewClient(peerIdentity, ciphersuite.MLS128DHKEMP256,
		mls.WithStorage(peerStore, peerStore),
		mls.WithCacheStrategy(mls.CacheNone),
	)
	if err != nil {
		t.Fatalf("mls.NewClient(peer): %v", err)
	}

	// --- Channel A: Discord adds the bot to an existing group. ---
	s.OnSelectProtocolAck(1)
	kpA := cb.lastKeyPackage()
	if len(kpA) == 0 {
		t.Fatal("expected a key package for channel A")
	}

	groupA, err := peer.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("peer.CreateGroup(A): %v", err)
	}
	_, welcomeA, err := peer.InviteMember(ctx, groupA, kpA)
	if err != nil {
		t.Fatalf("peer.InviteMember(A): %v", err)
	}
	s.OnDaveMLSWelcome(0, welcomeA)
	if got := s.Stats().WelcomesJoined; got != 1 {
		t.Fatalf("WelcomesJoined = %d, want 1 (failed = %d)", got, s.Stats().WelcomesFailed)
	}

	s.mu.RLock()
	if !bytes.Equal(s.groupID, groupA) {
		t.Errorf("groupID = %x, want %x", s.groupID, groupA)
	}
	if s.activeEpoch == nil || s.sendRatchet == nil {
		t.Fatal("expected an active epoch with a send ratchet after joining channel A")
	}
	s.mu.RUnlock()

	// --- The bot is moved to channel B. ---
	s.OnSelectProtocolAck(1)
	kpB := cb.lastKeyPackage()
	if bytes.Equal(kpA, kpB) {
		t.Fatal("expected a new key package for channel B")
	}

	s.mu.RLock()
	if s.groupID != nil {
		t.Errorf("groupID not cleared after move: %x", s.groupID)
	}
	if s.activeEpoch != nil {
		t.Error("activeEpoch not cleared after move")
	}
	s.mu.RUnlock()

	// --- A stale proposal batch for channel A's (discarded) group arrives late. ---
	// operation_type=0 (append) || TLSVector<MLSMessage> with length 0.
	staleProposals := []byte{0x00, 0x00}
	s.OnDaveMLSProposals(staleProposals)

	s.mu.RLock()
	if s.groupID != nil {
		t.Errorf("stale proposal corrupted groupID: %x", s.groupID)
	}
	if s.pendingEpoch != nil {
		t.Error("stale proposal created a pendingEpoch")
	}
	s.mu.RUnlock()

	// --- Channel B: Discord adds the bot to a new, unrelated group. ---
	groupB, err := peer.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("peer.CreateGroup(B): %v", err)
	}
	if bytes.Equal(groupA, groupB) {
		t.Fatal("test setup error: channel A and B groups must differ")
	}
	_, welcomeB, err := peer.InviteMember(ctx, groupB, kpB)
	if err != nil {
		t.Fatalf("peer.InviteMember(B): %v", err)
	}
	s.OnDaveMLSWelcome(0, welcomeB)
	if got := s.Stats().WelcomesJoined; got != 2 {
		t.Fatalf("WelcomesJoined = %d, want 2 (failed = %d)", got, s.Stats().WelcomesFailed)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if !bytes.Equal(s.groupID, groupB) {
		t.Errorf("groupID = %x, want %x (channel B)", s.groupID, groupB)
	}
	if s.activeEpoch == nil || s.sendRatchet == nil {
		t.Fatal("expected an active epoch with a send ratchet after joining channel B")
	}
	if len(s.retainedEpoch) != 0 {
		t.Errorf("retainedEpoch should be empty for a fresh post-move session: %+v", s.retainedEpoch)
	}
	if len(s.proposalQueue) != 0 {
		t.Errorf("proposalQueue should be empty for a fresh post-move session: %+v", s.proposalQueue)
	}
	if s.pendingCommitBytes != nil || s.preCommitGroupState != nil {
		t.Error("pendingCommitBytes/preCommitGroupState should be nil for a fresh post-move session")
	}
}
