package session

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

func setupActiveSoleMemberSessionWithKey(t *testing.T) (*Session, *ecdsa.PrivateKey) {
	t.Helper()

	pkg, extPriv := buildExternalSenderPackageWithKey(t)
	s := New("123456789", testCallbacks{})
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(pkg)
	s.OnDavePrepareTransition(0, 1)

	if s.groupID == nil || s.mlsClient == nil || s.activeEpoch == nil {
		t.Fatal("expected active sole-member MLS epoch to be initialized")
	}

	return s, extPriv
}

func addProposalBytesForUser(t *testing.T, s *Session, extPriv *ecdsa.PrivateKey, userID string) []byte {
	t.Helper()

	identity, err := userIDToIdentityBytes(godave.UserID(userID))
	if err != nil {
		t.Fatalf("userIDToIdentityBytes(%q): %v", userID, err)
	}

	return addProposalBytesAsExternalSender(t, s, extPriv, identity)
}

// addProposalBytesAsExternalSender is the same as addProposalBytesForUser but
// takes raw identity bytes directly, bypassing the 8-byte snowflake
// encoding — used to build a credential that parses fine at the MLS level
// but that identityBytesToUserID (which requires exactly 8 bytes) can't
// turn into a UserID.
func addProposalBytesForIdentity(t *testing.T, s *Session, extPriv *ecdsa.PrivateKey, identity []byte) []byte {
	t.Helper()

	return addProposalBytesAsExternalSender(t, s, extPriv, identity)
}

// addProposalBytesAsExternalSender builds an Add proposal signed by the
// external sender (the voice gateway), not by a group member. This mirrors
// how DAVE delivers proposals in reality (protocol.md:166: "Only Add and
// Remove proposals sent by the voice gateway external sender are allowed").
// The bot's own ProposeAddMember signs as SenderTypeMember, which the
// sender/type validation now rejects; tests must generate proposals the way
// the gateway actually would.
func addProposalBytesAsExternalSender(t *testing.T, s *Session, extPriv *ecdsa.PrivateKey, identity []byte) []byte {
	t.Helper()

	ctx := context.Background()

	store := memorystore.NewStore()
	member, err := mls.NewClient(identity, ciphersuite.MLS128DHKEMP256,
		mls.WithStorage(store, store),
		mls.WithCacheStrategy(mls.CacheNone),
	)
	if err != nil {
		t.Fatalf("mls.NewClient(identity=%x): %v", identity, err)
	}

	keyPackageBytes, err := member.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(identity=%x): %v", identity, err)
	}
	keyPackage, err := keypackages.UnmarshalKeyPackage(keyPackageBytes)
	if err != nil {
		t.Fatalf("UnmarshalKeyPackage: %v", err)
	}

	proposal := group.NewAddProposal(keyPackage)
	proposalData := group.ProposalMarshal(proposal)

	epoch, err := s.mlsClient.client.Epoch(ctx, s.groupID)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}

	groupInfoBytes, err := s.mlsClient.client.GroupInfo(ctx, s.groupID)
	if err != nil {
		t.Fatalf("GroupInfo: %v", err)
	}
	info, err := group.UnmarshalGroupInfo(groupInfoBytes)
	if err != nil {
		t.Fatalf("UnmarshalGroupInfo: %v", err)
	}
	gc := info.GroupContext.Marshal()

	content := framing.FramedContent{
		GroupID:           s.groupID,
		Epoch:             epoch,
		Sender:            framing.Sender{Type: framing.SenderTypeExternal, SenderIndex: 0},
		AuthenticatedData: []byte{},
		Body:              framing.ProposalBody{Data: proposalData},
	}

	sigKey := ciphersuite.NewSignaturePrivateKey(extPriv)
	pm, err := framing.NewPublicMessage(content, sigKey, gc, nil, ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("NewPublicMessage: %v", err)
	}

	return framing.NewMLSMessagePublic(pm).Marshal()
}

func memberCount(t *testing.T, s *Session) int {
	t.Helper()

	members, err := s.mlsClient.client.ListMembers(context.Background(), s.groupID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}

	return len(members)
}

func mutateMLSMessage(t *testing.T, wire []byte, mutate func(*framing.MLSMessage)) []byte {
	t.Helper()

	msg, err := framing.UnmarshalMLSMessage(wire)
	if err != nil {
		t.Fatalf("framing.UnmarshalMLSMessage: %v", err)
	}

	mutate(msg)

	return msg.Marshal()
}

func TestOnDaveMLSProposals_AddValidation(t *testing.T) {
	t.Run("ignores unexpected add", func(t *testing.T) {
		s, extPriv := setupActiveSoleMemberSessionWithKey(t)
		proposalBytes := addProposalBytesForUser(t, s, extPriv, "222222222")

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("initial member count = %d, want 1", got)
		}

		s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("member count after unexpected add = %d, want 1", got)
		}
		if got := s.Stats().ProposalsRejected; got != 1 {
			t.Fatalf("ProposalsRejected after unexpected add = %d, want 1", got)
		}
	})

	t.Run("accepts expected add", func(t *testing.T) {
		s, extPriv := setupActiveSoleMemberSessionWithKey(t)
		const expectedUserID = "333333333"
		s.AddUser(expectedUserID)
		proposalBytes := addProposalBytesForUser(t, s, extPriv, expectedUserID)

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("initial member count = %d, want 1", got)
		}

		s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

		if got := memberCount(t, s); got != 2 {
			t.Fatalf("member count after expected add = %d, want 2", got)
		}
		if got := s.Stats().ProposalsRejected; got != 0 {
			t.Fatalf("ProposalsRejected after accepted add = %d, want 0", got)
		}
	})

	// Covers the fail-closed path in addProposalUserID: a well-formed MLS Add
	// proposal whose credential identity isn't the 8-byte snowflake DAVE
	// expects. identityBytesToUserID fails on it, and the proposal must be
	// rejected rather than let through to ProcessPublicMessage unchecked.
	t.Run("rejects add whose identity fails inspection", func(t *testing.T) {
		s, extPriv := setupActiveSoleMemberSessionWithKey(t)
		proposalBytes := addProposalBytesForIdentity(t, s, extPriv, []byte{0x01, 0x02, 0x03})

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("initial member count = %d, want 1", got)
		}

		s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("member count after unparseable-identity add = %d, want 1 (must be rejected)", got)
		}
		if got := s.Stats().ProposalsRejected; got != 1 {
			t.Fatalf("ProposalsRejected after fail-closed inspection = %d, want 1", got)
		}
	})
}

func TestOnDaveMLSProposals_RejectsNewMemberProposalSender(t *testing.T) {
	s, extPriv := setupActiveSoleMemberSessionWithKey(t)
	proposalBytes := addProposalBytesForUser(t, s, extPriv, "222222222")

	mutated := mutateMLSMessage(t, proposalBytes, func(msg *framing.MLSMessage) {
		pub, _ := msg.AsPublic()
		pub.Content.Sender.Type = framing.SenderTypeNewMemberProposal
	})

	if got := memberCount(t, s); got != 1 {
		t.Fatalf("initial member count = %d, want 1", got)
	}

	s.OnDaveMLSProposals(buildProposalBatch(mutated))

	if got := memberCount(t, s); got != 1 {
		t.Fatalf("member count after disallowed sender = %d, want 1", got)
	}
	if got := s.Stats().ProposalsRejected; got != 1 {
		t.Fatalf("ProposalsRejected after disallowed sender = %d, want 1", got)
	}
}

func TestOnDaveMLSProposals_RejectsDisallowedProposalType(t *testing.T) {
	s, extPriv := setupActiveSoleMemberSessionWithKey(t)
	proposalBytes := addProposalBytesForUser(t, s, extPriv, "222222222")

	mutated := mutateMLSMessage(t, proposalBytes, func(msg *framing.MLSMessage) {
		pub, _ := msg.AsPublic()
		pub.Content.Body = framing.ProposalBody{
			Data: group.ProposalMarshal(group.NewPreSharedKeyProposal(1, []byte("psk"))),
		}
	})

	if got := memberCount(t, s); got != 1 {
		t.Fatalf("initial member count = %d, want 1", got)
	}

	s.OnDaveMLSProposals(buildProposalBatch(mutated))

	if got := memberCount(t, s); got != 1 {
		t.Fatalf("member count after disallowed proposal type = %d, want 1", got)
	}
	if got := s.Stats().ProposalsRejected; got != 1 {
		t.Fatalf("ProposalsRejected after disallowed proposal type = %d, want 1", got)
	}
}
