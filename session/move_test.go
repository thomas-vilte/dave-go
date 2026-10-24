package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
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

// shardDownCallbacks fails SendMLSCommitWelcome with "shard is not ready" and
// counts the other sends, so tests can see the recovery watchdog fire.
type shardDownCallbacks struct {
	countingCallbacks
}

func (c *shardDownCallbacks) SendMLSCommitWelcome([]byte) error {
	return errors.New("shard is not ready")
}

// failingKPCallbacks fails the first failures key package sends with a
// non-transient error, then captures the rest.
type failingKPCallbacks struct {
	kpCapturingCallbacks
	failures int
}

func (c *failingKPCallbacks) SendMLSKeyPackage(kp []byte) error {
	c.mu.Lock()
	if c.failures > 0 {
		c.failures--
		c.mu.Unlock()

		return errors.New("websocket: close sent")
	}
	c.mu.Unlock()

	return c.kpCapturingCallbacks.SendMLSKeyPackage(kp)
}

// TestExternalSenderPackage_ResendsUnsentKeyPackage verifies that a key package
// the gateway never received is not used to build the MLS group: the session
// sends a fresh one first, and builds no group if that send fails too.
func TestExternalSenderPackage_ResendsUnsentKeyPackage(t *testing.T) {
	tests := []struct {
		name      string
		failures  int
		wantGroup bool
	}{
		{name: "resend succeeds", failures: 1, wantGroup: true},
		{name: "resend fails", failures: 2, wantGroup: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := &failingKPCallbacks{failures: tt.failures}
			s := New("123456789", cb)
			closeAtCleanup(t, s)
			s.SetChannelID(987654321)
			s.OnSelectProtocolAck(1)
			s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))

			s.mu.RLock()
			defer s.mu.RUnlock()
			if got := len(s.groupID) > 0; got != tt.wantGroup {
				t.Fatalf("group created = %v, want %v", got, tt.wantGroup)
			}
			if !tt.wantGroup {
				return
			}
			if !bytes.Equal(s.pendingKeyPackage, cb.lastKeyPackage()) {
				t.Fatal("group built from a key package the gateway never received")
			}
		})
	}
}

// TestOnSelectProtocolAck_DiscardsPreviousChannelState verifies that
// select_protocol_ack (sent by Discord whenever the bot joins/moves to a
// voice channel) fully discards an established session's MLS/epoch state and
// starts the new connection from scratch, with a fresh MLS client and key
// package.
func TestOnSelectProtocolAck_DiscardsPreviousChannelState(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

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
	s := New("123456789", cb)

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

// TestCommitSend_ShardNotReady_RollsBackAndArmsRecovery verifies that when
// SendMLSCommitWelcome fails because the voice gateway is down ("shard is not
// ready"), commitProposalsLocked rolls the local MLS epoch back to its
// pre-commit state and arms the recovery watchdog, since a resumed connection
// brings no OnSelectProtocolAck to reset the session.
func TestCommitSend_ShardNotReady_RollsBackAndArmsRecovery(t *testing.T) {
	cb := &shardDownCallbacks{}
	s, extPriv := setupActiveSoleMemberSessionWithKey(t)
	s.callbacks = cb
	s.recoveryTimeout = 10 * time.Millisecond

	const joiner = "222222222"
	s.AddUser(joiner)
	s.OnDaveMLSProposals(buildProposalBatch(addProposalBytesForUser(t, s, extPriv, joiner)))

	s.mu.RLock()
	if s.pendingEpoch != nil || s.pendingCommitBytes != nil || s.preCommitGroupState != nil {
		t.Error("pending commit state left behind after the commit was dropped")
	}
	epoch, err := s.mlsClient.client.Epoch(context.Background(), s.groupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if epoch != s.activeEpoch.id {
		t.Errorf("group at epoch %d, want %d (not rolled back)", epoch, s.activeEpoch.id)
	}
	s.mu.RUnlock()

	eventually(t, func() bool {
		invalid, _ := cb.counts()

		return invalid > 0
	}, "recovery watchdog not armed after the commit was dropped")
}

// TestOnSelectProtocolAck_V0AfterMoveDropsSendKey covers a session moved from
// an E2EE channel to one without: listeners there can't decrypt the old key,
// so ack(0) must leave the session as a fresh version 0 session would be.
func TestOnSelectProtocolAck_V0AfterMoveDropsSendKey(t *testing.T) {
	s := New("123456789", testCallbacks{})
	closeAtCleanup(t, s)
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.OnDavePrepareTransition(0, 1)

	plaintext := []byte("audio")
	out := make([]byte, s.MaxEncryptedFrameSize(len(plaintext)))
	n, err := s.Encrypt(1, plaintext, out)
	if err != nil || !frame.LooksLikeDAVEFrame(out[:n]) {
		t.Fatalf("SETUP: Encrypt = %x, %v; want a DAVE frame", out[:n], err)
	}
	transitionWindows := s.Stats().TransitionWindows
	s.mu.Lock()
	hadActiveEpoch := s.activeEpoch != nil
	s.pendingEpoch = &epochState{id: 6}
	s.retainedEpoch = []*epochState{{id: 4}}
	s.mu.Unlock()
	if !hadActiveEpoch {
		t.Fatal("SETUP: no active epoch before the move")
	}

	s.SetChannelID(111111111)
	s.OnSelectProtocolAck(0)

	n, err = s.Encrypt(1, plaintext, out)
	if err != nil || !bytes.Equal(out[:n], plaintext) {
		t.Fatalf("Encrypt after the move = %x, %v; want the frame passed through", out[:n], err)
	}
	if got := s.State(); got != (State{}) {
		t.Errorf("State() = %+v, want the zero State of a fresh version 0 session", got)
	}
	if !s.Ready() {
		t.Error("Ready() = false, want true at version 0")
	}
	if got := s.Stats().TransitionWindows; got != transitionWindows {
		t.Errorf("TransitionWindows = %d, want %d: the old key was retained", got, transitionWindows)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeEpoch != nil || s.pendingEpoch != nil || s.retainedEpoch != nil {
		t.Errorf("activeEpoch %+v, pendingEpoch %+v, retainedEpoch %+v; want all nil",
			s.activeEpoch, s.pendingEpoch, s.retainedEpoch)
	}
	if s.groupID != nil || s.mlsClient != nil || s.pendingKeyPackage != nil || s.retainedSendRatchet != nil || s.sendCipher != nil {
		t.Errorf("groupID %x, mlsClient set %v, pendingKeyPackage %x, retainedSendRatchet set %v, sendCipher set %v; want all cleared",
			s.groupID, s.mlsClient != nil, s.pendingKeyPackage, s.retainedSendRatchet != nil, s.sendCipher != nil)
	}
}

// TestOnSelectProtocolAck_V0StopsRecovery checks that a recovery watchdog
// armed on the previous connection doesn't fire after a move to version 0.
func TestOnSelectProtocolAck_V0StopsRecovery(t *testing.T) {
	cb := &countingCallbacks{}
	s := newRecoveryTestSession(t, cb)
	s.lockMLS()
	s.invalidateAndResendKeyPackageLocked()
	s.recoveryAttempts = 1
	s.unlockMLS()
	invalidBefore, _ := cb.counts()

	s.OnSelectProtocolAck(0)
	time.Sleep(10 * s.recoveryTimeout)

	if invalid, _ := cb.counts(); invalid != invalidBefore {
		t.Errorf("invalid_commit_welcome sent %d times after the move, want 0", invalid-invalidBefore)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.recoveryAttempts != 0 {
		t.Errorf("recoveryAttempts = %d, want 0", s.recoveryAttempts)
	}
}

// TestOnSelectProtocolAck_EndsDegradedInterval checks that an ack, as the
// start of a new connection, clears DegradedSince without losing the interval
// from DegradedDuration.
func TestOnSelectProtocolAck_EndsDegradedInterval(t *testing.T) {
	for _, version := range []uint16{0, 1} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			s := New("123456789", testCallbacks{})
			closeAtCleanup(t, s)
			const degradedFor = time.Second
			s.mu.Lock()
			s.degradedSince = time.Now().Add(-degradedFor)
			s.mu.Unlock()

			s.OnSelectProtocolAck(version)

			if got := s.State().DegradedSince; !got.IsZero() {
				t.Errorf("DegradedSince = %v, want zero", got)
			}
			got := s.Stats().DegradedDuration
			if got < degradedFor {
				t.Fatalf("DegradedDuration = %v, want >= %v", got, degradedFor)
			}

			s.OnSelectProtocolAck(version)

			if again := s.Stats().DegradedDuration; again != got {
				t.Errorf("DegradedDuration = %v after a second ack, want %v unchanged", again, got)
			}
		})
	}
}
