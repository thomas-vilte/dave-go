package session

import (
	"context"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

func setupActiveSoleMemberSession(t *testing.T) *session {
	t.Helper()

	s := New(nil, "123456789", testCallbacks{}).(*session)
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.OnDavePrepareTransition(0, 1)

	if s.groupID == nil || s.mlsClient == nil || s.activeEpoch == nil {
		t.Fatal("expected active sole-member MLS epoch to be initialized")
	}

	return s
}

func addProposalBytesForUser(t *testing.T, s *session, userID string) []byte {
	t.Helper()

	identity, err := userIDToIdentityBytes(godave.UserID(userID))
	if err != nil {
		t.Fatalf("userIDToIdentityBytes(%q): %v", userID, err)
	}

	return addProposalBytesForIdentity(t, s, identity)
}

// addProposalBytesForIdentity is the same as addProposalBytesForUser but
// takes raw identity bytes directly, bypassing the 8-byte snowflake
// encoding — used to build a credential that parses fine at the MLS level
// but that identityBytesToUserID (which requires exactly 8 bytes) can't
// turn into a UserID.
func addProposalBytesForIdentity(t *testing.T, s *session, identity []byte) []byte {
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

	keyPackage, err := member.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(identity=%x): %v", identity, err)
	}

	proposalBytes, err := s.mlsClient.client.ProposeAddMember(ctx, s.groupID, keyPackage)
	if err != nil {
		t.Fatalf("ProposeAddMember(identity=%x): %v", identity, err)
	}
	if err := s.mlsClient.client.CancelPendingProposals(ctx, s.groupID); err != nil {
		t.Fatalf("CancelPendingProposals(identity=%x): %v", identity, err)
	}

	return proposalBytes
}

func memberCount(t *testing.T, s *session) int {
	t.Helper()

	members, err := s.mlsClient.client.ListMembers(context.Background(), s.groupID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}

	return len(members)
}

func TestOnDaveMLSProposals_AddValidation(t *testing.T) {
	t.Run("ignores unexpected add", func(t *testing.T) {
		s := setupActiveSoleMemberSession(t)
		proposalBytes := addProposalBytesForUser(t, s, "222222222")

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("initial member count = %d, want 1", got)
		}

		s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("member count after unexpected add = %d, want 1", got)
		}
	})

	t.Run("accepts expected add", func(t *testing.T) {
		s := setupActiveSoleMemberSession(t)
		const expectedUserID = "333333333"
		s.AddUser(expectedUserID)
		proposalBytes := addProposalBytesForUser(t, s, expectedUserID)

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("initial member count = %d, want 1", got)
		}

		s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

		if got := memberCount(t, s); got != 2 {
			t.Fatalf("member count after expected add = %d, want 2", got)
		}
	})

	// Covers the fail-closed path in addProposalUserID: a well-formed MLS Add
	// proposal whose credential identity isn't the 8-byte snowflake DAVE
	// expects. identityBytesToUserID fails on it, and the proposal must be
	// rejected rather than let through to ProcessPublicMessage unchecked.
	t.Run("rejects add whose identity fails inspection", func(t *testing.T) {
		s := setupActiveSoleMemberSession(t)
		proposalBytes := addProposalBytesForIdentity(t, s, []byte{0x01, 0x02, 0x03})

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("initial member count = %d, want 1", got)
		}

		s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

		if got := memberCount(t, s); got != 1 {
			t.Fatalf("member count after unparseable-identity add = %d, want 1 (must be rejected)", got)
		}
	})
}
