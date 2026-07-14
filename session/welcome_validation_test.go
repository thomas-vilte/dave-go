package session

import (
	"bytes"
	"context"
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

	ctx := context.Background()
	peer := peerWithIdentity(t, "987654321")
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

	return groupID, welcome
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
