package session

import (
	"context"
	"errors"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

// freshKeyPackageBytesForIdentity builds a fresh MLS key package for the given
// raw identity bytes. Two calls with the same identity produce packages with
// the SAME credential identity but DIFFERENT keys — used to force a group with
// two members sharing a user ID.
func freshKeyPackageBytesForIdentity(t *testing.T, identity []byte) []byte {
	t.Helper()

	store := memorystore.NewStore()
	member, err := mls.NewClient(identity, ciphersuite.MLS128DHKEMP256,
		mls.WithStorage(store, store),
		mls.WithCacheStrategy(mls.CacheNone),
	)
	if err != nil {
		t.Fatalf("mls.NewClient(identity=%x): %v", identity, err)
	}
	kp, err := member.FreshKeyPackageBytes(context.Background())
	if err != nil {
		t.Fatalf("FreshKeyPackageBytes(identity=%x): %v", identity, err)
	}

	return kp
}

// TestValidateCommitProposalRefs_AcceptsReferenceCommit is the false-positive
// guard: a real reference-based DAVE commit (what mls-go produces) must pass,
// otherwise every foreign commit would be rejected in production.
func TestValidateCommitProposalRefs_AcceptsReferenceCommit(t *testing.T) {
	s, extPriv := setupActiveSoleMemberSessionWithKey(t)
	const expectedUserID = "333333333"
	s.AddUser(expectedUserID)
	proposalBytes := addProposalBytesForUser(t, s, extPriv, expectedUserID)

	// Drives commitProposalsLocked, which stores our real reference-based commit.
	s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))
	if len(s.pendingCommitBytes) == 0 {
		t.Fatal("expected a real commit to have been produced")
	}

	if err := validateCommitProposalRefs(s.pendingCommitBytes); err != nil {
		t.Fatalf("real reference-based commit must pass, got: %v", err)
	}
}

// TestValidateCommitProposalRefs_RejectsInlineProposal takes a real member
// commit and rewrites its body to embed a proposal inline (ProposalOrRef type
// 1) instead of a cached reference, then confirms it is rejected per
// protocol.md:314. Starting from a real commit keeps the membership tag present
// so the message still parses (validateCommitProposalRefs is structural — it
// verifies neither the signature nor the tag).
func TestValidateCommitProposalRefs_RejectsInlineProposal(t *testing.T) {
	s, extPriv := setupActiveSoleMemberSessionWithKey(t)
	const expectedUserID = "333333333"
	s.AddUser(expectedUserID)
	proposalBytes := addProposalBytesForUser(t, s, extPriv, expectedUserID)
	s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))
	if len(s.pendingCommitBytes) == 0 {
		t.Fatal("expected a real commit to have been produced")
	}

	// An inline Add proposal to graft into the commit body.
	kpBytes := freshKeyPackageBytesForIdentity(t, mustIdentity(t, "222222222"))
	kp, err := keypackages.UnmarshalKeyPackage(kpBytes)
	if err != nil {
		t.Fatalf("UnmarshalKeyPackage: %v", err)
	}
	inlineCommit := &group.Commit{
		Proposals: []group.ProposalOrRef{{Proposal: group.NewAddProposal(kp)}},
	}

	mutated := mutateMLSMessage(t, s.pendingCommitBytes, func(msg *framing.MLSMessage) {
		pub, ok := msg.AsPublic()
		if !ok {
			t.Fatal("real commit is not a public message")
		}
		pub.Content.Body = framing.CommitBody{Data: inlineCommit.Marshal()}
	})

	if err := validateCommitProposalRefs(mutated); !errors.Is(err, ErrInlineProposalInCommit) {
		t.Fatalf("expected ErrInlineProposalInCommit, got: %v", err)
	}
}

// TestRebuildEpochState_RejectsDuplicateIdentity forces a group with two members
// sharing the same user ID (different keys, same credential identity) — which
// mls-go allows since it only enforces key uniqueness — and confirms
// rebuildEpochStateLocked rejects it per protocol.md:315.
func TestRebuildEpochState_RejectsDuplicateIdentity(t *testing.T) {
	s, _ := setupActiveSoleMemberSessionWithKey(t)
	ctx := context.Background()

	identity := mustIdentity(t, "222222222")
	kpA := freshKeyPackageBytesForIdentity(t, identity)
	kpB := freshKeyPackageBytesForIdentity(t, identity)

	// Two add proposals for the same identity, different keys.
	if _, err := s.mlsClient.client.ProposeAddMember(ctx, s.groupID, kpA); err != nil {
		t.Fatalf("ProposeAddMember(A): %v", err)
	}
	if _, err := s.mlsClient.client.ProposeAddMember(ctx, s.groupID, kpB); err != nil {
		t.Fatalf("ProposeAddMember(B): %v", err)
	}
	if _, _, err := s.mlsClient.client.CommitPendingProposals(ctx, s.groupID); err != nil {
		t.Fatalf("CommitPendingProposals: %v", err)
	}

	// The group now has two members with user ID 222222222.
	if _, err := s.rebuildEpochStateLocked(s.groupID); !errors.Is(err, ErrDuplicateGroupIdentity) {
		t.Fatalf("expected ErrDuplicateGroupIdentity, got: %v", err)
	}
}

func mustIdentity(t *testing.T, userID string) []byte {
	t.Helper()
	id, err := userIDToIdentityBytes(godave.UserID(userID))
	if err != nil {
		t.Fatalf("userIDToIdentityBytes(%q): %v", userID, err)
	}

	return id
}
