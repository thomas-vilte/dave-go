package session

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

func setExternalSenderPackage(t *testing.T, s *Session, pkg []byte) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.externalSenderPackage = append([]byte(nil), pkg...)
}

func peerWithIdentity(t *testing.T, userID string) *mls.Client {
	t.Helper()

	identity, err := userIDToIdentityBytes(godave.UserID(userID))
	if err != nil {
		t.Fatalf("userIDToIdentityBytes(%q): %v", userID, err)
	}

	store := memorystore.NewStore()
	peer, err := mls.NewClient(identity, ciphersuite.MLS128DHKEMP256,
		mls.WithStorage(store, store),
		mls.WithCacheStrategy(mls.CacheNone),
	)
	if err != nil {
		t.Fatalf("mls.NewClient(%q): %v", userID, err)
	}

	return peer
}

func newWelcomeForExternalSender(t *testing.T, botKP, externalSenderPackage []byte) (groupID, welcome []byte) {
	t.Helper()
	_, groupID, welcome = newPeerGroupForExternalSender(t, botKP, externalSenderPackage)

	return groupID, welcome
}

func newPeerGroupForExternalSender(t *testing.T, botKP, externalSenderPackage []byte) (peer *mls.Client, groupID, welcome []byte) {
	t.Helper()

	ctx := context.Background()
	peer = peerWithIdentity(t, "987654321")
	peerKP, err := peer.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("peer.FreshKeyPackageBytes: %v", err)
	}
	groupID, err = peer.CreateGroupWithExternalSender(ctx, []byte("12345678"), peerKP, externalSenderPackage)
	if err != nil {
		t.Fatalf("CreateGroupWithExternalSender: %v", err)
	}
	_, welcome, err = peer.InviteMember(ctx, groupID, botKP)
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}

	return peer, groupID, welcome
}

func TestOnDaveMLSWelcome_ValidatesExternalSender(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	botKP := cb.lastKeyPackage()
	if len(botKP) == 0 {
		t.Fatal("expected a key package after protocol ack")
	}

	externalSenderPackage := buildExternalSenderPackage(t)
	setExternalSenderPackage(t, s, externalSenderPackage)

	groupID, welcome := newWelcomeForExternalSender(t, botKP, externalSenderPackage)
	if len(groupID) == 0 || len(welcome) == 0 {
		t.Fatal("test setup produced empty groupID/welcome")
	}

	s.OnDaveMLSWelcome(0, welcome)

	if got := s.Stats().WelcomesJoined; got != 1 {
		t.Fatalf("WelcomesJoined = %d, want 1 (failed = %d)", got, s.Stats().WelcomesFailed)
	}
	if got := s.Stats().WelcomesFailed; got != 0 {
		t.Fatalf("WelcomesFailed = %d, want 0", got)
	}
	s.mu.RLock()
	if !bytes.Equal(s.groupID, groupID) {
		t.Fatalf("groupID = %x, want %x", s.groupID, groupID)
	}
	s.mu.RUnlock()
	if got := len(cb.keyPackages); got != 1 {
		t.Fatalf("key package resend count = %d, want 1", got)
	}
}

func TestOnDaveMLSWelcome_RejectsMismatchedExternalSender(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	closeAtCleanup(t, s)
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	botKP := cb.lastKeyPackage()
	if len(botKP) == 0 {
		t.Fatal("expected a key package after protocol ack")
	}

	storedPackage := buildExternalSenderPackage(t)
	groupPackage := buildExternalSenderPackage(t)
	for bytes.Equal(storedPackage, groupPackage) {
		groupPackage = buildExternalSenderPackage(t)
	}
	setExternalSenderPackage(t, s, storedPackage)

	_, welcome := newWelcomeForExternalSender(t, botKP, groupPackage)
	s.OnDaveMLSWelcome(0, welcome)

	if got := s.Stats().WelcomesFailed; got != 1 {
		t.Fatalf("WelcomesFailed = %d, want 1", got)
	}
	if got := s.Stats().WelcomesJoined; got != 0 {
		t.Fatalf("WelcomesJoined = %d, want 0", got)
	}
	s.mu.RLock()
	if s.groupID != nil {
		t.Fatalf("groupID should be cleared after invalid welcome, got %x", s.groupID)
	}
	s.mu.RUnlock()
	if got := len(cb.keyPackages); got < 2 {
		t.Fatalf("expected key package resend after invalid welcome, got %d sends", got)
	}
}

// invalidCountingCallbacks captures key packages and counts
// invalid_commit_welcome messages.
type invalidCountingCallbacks struct {
	kpCapturingCallbacks
	invalid atomic.Int32
}

func (c *invalidCountingCallbacks) SendInvalidCommitWelcome(uint16) error {
	c.invalid.Add(1)

	return nil
}

// TestOnDaveMLSWelcome_OverPeerPendingEpoch verifies that a Welcome over a
// pending epoch the session did not commit itself takes the failed-Welcome
// path: joining the first group used up the key package, so the session
// flags the Welcome, sends a new key package and arms the recovery watchdog.
func TestOnDaveMLSWelcome_OverPeerPendingEpoch(t *testing.T) {
	tests := []struct {
		name                string
		welcomeTransitionID uint16
		peerCommit          bool
	}{
		{name: "welcome not executed", welcomeTransitionID: 5},
		{name: "peer commit not executed", peerCommit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := &invalidCountingCallbacks{}
			s := New("123456789", cb)
			closeAtCleanup(t, s)
			s.SetChannelID(987654321)
			s.OnSelectProtocolAck(1)
			externalSenderPackage := buildExternalSenderPackage(t)
			setExternalSenderPackage(t, s, externalSenderPackage)
			botKP := cb.lastKeyPackage()
			peer, groupID, welcome := newPeerGroupForExternalSender(t, botKP, externalSenderPackage)
			s.OnDaveMLSWelcome(tt.welcomeTransitionID, welcome)
			transitionID := tt.welcomeTransitionID
			if tt.peerCommit {
				commit, _, err := peer.CommitPendingProposals(context.Background(), groupID)
				if err != nil {
					t.Fatalf("peer.CommitPendingProposals: %v", err)
				}
				transitionID++
				s.OnDaveMLSPrepareCommitTransition(transitionID, commit)
			}
			s.mu.RLock()
			pending := s.pendingEpoch != nil
			s.mu.RUnlock()
			if !pending {
				t.Fatal("test setup left no pending epoch")
			}

			_, _, newWelcome := newPeerGroupForExternalSender(t, botKP, externalSenderPackage)
			s.OnDaveMLSWelcome(transitionID+1, newWelcome)

			stats := s.Stats()
			if stats.WelcomesJoined != 1 || stats.WelcomesFailed != 1 {
				t.Fatalf("WelcomesJoined = %d, WelcomesFailed = %d, want 1 and 1", stats.WelcomesJoined, stats.WelcomesFailed)
			}
			if invalid := cb.invalid.Load(); invalid != 1 {
				t.Fatalf("invalid_commit_welcome sent %d times, want 1", invalid)
			}
			if kp := cb.lastKeyPackage(); bytes.Equal(kp, botKP) {
				t.Fatal("no new key package sent after the failed Welcome")
			}
			if stats.RecoveryAttempts != 1 {
				t.Fatalf("RecoveryAttempts = %d, want 1", stats.RecoveryAttempts)
			}
		})
	}
}

// TestOnDaveMLSWelcome_AfterOwnCommit verifies that a Welcome after our own
// commit rolls the commit back, drops the queued proposals and joins.
func TestOnDaveMLSWelcome_AfterOwnCommit(t *testing.T) {
	ctx := context.Background()
	cb := &invalidCountingCallbacks{}
	s := New("123456789", cb)
	closeAtCleanup(t, s)
	externalSenderPackage, extPriv := buildExternalSenderPackageWithKey(t)
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	botKP := cb.lastKeyPackage()
	s.OnDaveMLSExternalSenderPackage(externalSenderPackage)
	s.OnDavePrepareTransition(0, 1)

	for _, joiner := range []string{"222222222", "333333333"} {
		s.AddUser(godave.UserID(joiner))
		s.OnDaveMLSProposals(buildProposalBatch(addProposalBytesForUser(t, s, extPriv, joiner)))
	}
	s.mu.RLock()
	committed, queued := len(s.pendingCommitBytes) > 0, len(s.proposalQueue)
	s.mu.RUnlock()
	if !committed || queued != 1 {
		t.Fatalf("committed = %v with %d queued batches, want a commit and 1 queued batch", committed, queued)
	}

	peer, groupID, welcome := newPeerGroupForExternalSender(t, botKP, externalSenderPackage)
	s.OnDaveMLSWelcome(1, welcome)

	stats := s.Stats()
	if stats.WelcomesJoined != 1 || stats.WelcomesFailed != 0 {
		t.Fatalf("WelcomesJoined = %d, WelcomesFailed = %d, want 1 and 0", stats.WelcomesJoined, stats.WelcomesFailed)
	}
	if invalid := cb.invalid.Load(); invalid != 0 {
		t.Fatalf("invalid_commit_welcome sent %d times, want 0", invalid)
	}
	wantEpoch, err := peer.Epoch(ctx, groupID)
	if err != nil {
		t.Fatalf("peer.Epoch: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pendingEpoch == nil || s.pendingEpoch.id != wantEpoch {
		t.Fatalf("pending epoch = %+v, want epoch %d", s.pendingEpoch, wantEpoch)
	}
	if len(s.pendingCommitBytes) != 0 || len(s.proposalQueue) != 0 {
		t.Fatalf("%d bytes of our commit and %d queued batches left after the Welcome", len(s.pendingCommitBytes), len(s.proposalQueue))
	}
}
