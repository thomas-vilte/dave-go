package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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

// shardDownCallbacks captures key packages (so the MLS flow can proceed) but
// fails SendMLSCommitWelcome with "shard is not ready" and counts
// SendInvalidCommitWelcome calls so tests can assert no watchdog fired.
type shardDownCallbacks struct {
	mu             sync.Mutex
	keyPackages    [][]byte
	invalidCommits int
}

func (c *shardDownCallbacks) SendMLSKeyPackage(kp []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages = append(c.keyPackages, append([]byte(nil), kp...))

	return nil
}

func (c *shardDownCallbacks) SendMLSCommitWelcome([]byte) error {
	return errors.New("shard is not ready")
}

func (c *shardDownCallbacks) SendReadyForTransition(uint16) error { return nil }

func (c *shardDownCallbacks) SendInvalidCommitWelcome(uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidCommits++

	return nil
}

func (c *shardDownCallbacks) lastKeyPackage() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keyPackages) == 0 {
		return nil
	}

	return c.keyPackages[len(c.keyPackages)-1]
}

func (c *shardDownCallbacks) invalidCommitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.invalidCommits
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
	externalSenderPackage := buildExternalSenderPackage(t)
	setExternalSenderPackage(t, s, externalSenderPackage)
	kpA := cb.lastKeyPackage()
	if len(kpA) == 0 {
		t.Fatal("expected a key package for channel A")
	}

	peerKP, err := peer.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("peer.FreshKeyPackageBytes(A): %v", err)
	}
	groupA, err := peer.CreateGroupWithExternalSender(ctx, []byte("group-A"), peerKP, externalSenderPackage)
	if err != nil {
		t.Fatalf("peer.CreateGroupWithExternalSender(A): %v", err)
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
	peerKP, err = peer.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("peer.FreshKeyPackageBytes(B): %v", err)
	}
	groupB, err := peer.CreateGroupWithExternalSender(ctx, []byte("group-B"), peerKP, externalSenderPackage)
	if err != nil {
		t.Fatalf("peer.CreateGroupWithExternalSender(B): %v", err)
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

// buildProposalBatch encodes proposal bytes in the DAVE_MLSProposals wire format:
// operation_type(0x00=append) || TLSVector<MLSMessage>.
func buildProposalBatch(proposalBytes []byte) []byte {
	return append([]byte{0x00}, writeVLBytes(proposalBytes)...)
}

// TestCommitSend_ShardNotReady_RollsBackAndNoWatchdog verifies the fix for
// (commit path): when SendMLSCommitWelcome fails because the
// voice gateway is transiently down ("shard is not ready"), commitProposalsLocked
// must roll back the local MLS epoch to its pre-commit state and return without
// arming the recovery watchdog — re-arming it would just loop on a transport
// problem. The natural OnSelectProtocolAck on reconnect resets the session cleanly.
func TestCommitSend_ShardNotReady_RollsBackAndNoWatchdog(t *testing.T) {
	ctx := context.Background()
	cb := &shardDownCallbacks{}
	s := New(nil, "123456789", cb).(*session)
	s.recoveryTimeout = 10 * time.Millisecond

	// --- Bot joins an established group (channel A). ---
	s.OnSelectProtocolAck(1)
	externalSenderPackage := buildExternalSenderPackage(t)
	setExternalSenderPackage(t, s, externalSenderPackage)
	botKP := cb.lastKeyPackage()
	if len(botKP) == 0 {
		t.Fatal("expected a key package after OnSelectProtocolAck")
	}

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

	peerKP, err := peer.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("peer.FreshKeyPackageBytes: %v", err)
	}
	groupID, err := peer.CreateGroupWithExternalSender(ctx, []byte("group-shard"), peerKP, externalSenderPackage)
	if err != nil {
		t.Fatalf("peer.CreateGroupWithExternalSender: %v", err)
	}

	_, welcome, err := peer.InviteMember(ctx, groupID, botKP)
	if err != nil {
		t.Fatalf("peer.InviteMember(bot): %v", err)
	}

	s.OnDaveMLSWelcome(0, welcome)
	if s.Stats().WelcomesJoined != 1 {
		t.Fatalf("bot did not join welcome: WelcomesJoined=%d WelcomesFailed=%d",
			s.Stats().WelcomesJoined, s.Stats().WelcomesFailed)
	}

	s.mu.RLock()
	if s.activeEpoch == nil || s.sendRatchet == nil {
		t.Fatal("expected active epoch after joining welcome")
	}
	s.mu.RUnlock()

	// --- A new member wants to join: peer creates an add proposal. ---
	newMemberStore := memorystore.NewStore()
	newMemberIdentity, err := userIDToIdentityBytes("111111111")
	if err != nil {
		t.Fatalf("userIDToIdentityBytes(new member): %v", err)
	}

	newMember, err := mls.NewClient(newMemberIdentity, ciphersuite.MLS128DHKEMP256,
		mls.WithStorage(newMemberStore, newMemberStore),
		mls.WithCacheStrategy(mls.CacheNone),
	)
	if err != nil {
		t.Fatalf("mls.NewClient(newMember): %v", err)
	}

	newMemberKP, err := newMember.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("newMember.FreshKeyPackageBytes: %v", err)
	}

	proposalBytes, err := peer.ProposeAddMember(ctx, groupID, newMemberKP)
	if err != nil {
		t.Fatalf("peer.ProposeAddMember: %v", err)
	}

	// --- Gateway sends the proposal to the bot; bot tries to commit but shard is down. ---
	s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

	// --- Verify: local MLS state rolled back, no watchdog armed. ---
	s.mu.RLock()
	pendingEpoch := s.pendingEpoch
	preCommitState := s.preCommitGroupState
	s.mu.RUnlock()

	if pendingEpoch != nil {
		t.Error("pendingEpoch should be nil after transport rollback")
	}

	if preCommitState != nil {
		t.Error("preCommitGroupState should be nil after transport rollback")
	}

	// Wait well past the recovery timeout; without the fix the watchdog would fire.
	time.Sleep(5 * s.recoveryTimeout)

	if n := cb.invalidCommitCount(); n != 0 {
		t.Errorf("recovery watchdog fired despite transport failure: %d SendInvalidCommitWelcome calls", n)
	}
}
