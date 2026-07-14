package session

import (
	"strings"
	"sync"
	"testing"
)

// buildRevokeBatch builds a DAVE opcode 27 payload with operation_type=1 (revoke):
// uint8(1) || TLSVector<ProposalRef[32 bytes]>. The wire format is documented in
// protocol.md:1020-1048.
func buildRevokeBatch(refs []byte) []byte {
	return append([]byte{0x01}, writeVLBytes(refs)...)
}

// TestProcessRevokeProposalsLocked_WireFormat covers the parsing of the revoke
// branch (operation_type=1) in processProposalBatchLocked without requiring a
// real MLS group or network — it validates the TLSVector format, the 32-byte
// ProposalRef alignment, and the defensive ceilings. The real happy path
// (valid refs → g.RevokeProposal) is covered in mls-go with a real peer.
func TestProcessRevokeProposalsLocked_WireFormat(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	// OnSelectProtocolAck with a non-zero version initializes s.mlsClient (see
	// ensureMLSClientLocked in mls.go). Without this, RevokeProposals would
	// panic on s.mlsClient == nil.
	s.OnSelectProtocolAck(1)

	// Set an arbitrary groupID (not present in the store) so the handler
	// reaches RevokeProposals; loadGroupEntry fails with "no such group",
	// which gets wrapped in "revoke proposals:" — exactly what we match
	// against in wantErr.
	s.mu.Lock()
	s.groupID = []byte("group-nonexistent")
	s.mu.Unlock()

	cases := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{"empty refs batch", buildRevokeBatch(nil), ""},
		{"one valid ref 32 bytes", buildRevokeBatch(make([]byte, 32)), "revoke proposals:"},
		{"two valid refs 64 bytes", buildRevokeBatch(make([]byte, 64)), "revoke proposals:"},
		{"bad body len not multiple of 32", buildRevokeBatch(make([]byte, 33)), "not multiple of 32"},
		{"truncated vector", []byte{0x01, 0x20}, "truncated"},
		{"too many refs exceeds maxRevokeRefs", buildRevokeBatch(make([]byte, maxRevokeRefs*32+32)), "too many"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// processRevokeProposalsLocked receives the payload after
			// operation_type (the first byte), so we strip it here.
			payload := tc.payload[1:]

			err := s.processRevokeProposalsLocked(payload)
			switch {
			case tc.wantErr == "":
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case err == nil:
				t.Errorf("expected error containing %q, got nil", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("err = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestOnDaveMLSProposals_RevokeSkipsCommit verifies that a revoke batch
// (operation_type=1) with empty refs (the success path) does not trigger
// SendMLSCommitWelcome — the spec only requires committing "if there are one
// or more cached proposals after processing" (protocol.md:176), and revoke
// only removes. We use a real group built by ensureMLSClientLocked so the
// handler doesn't abort on a missing group; with 0 refs, the revoke is a
// no-op by design (idempotent), and our early return skips the commit.
func TestOnDaveMLSProposals_RevokeSkipsCommit(t *testing.T) {
	cb := &commitCountingCallbacks{}
	s := New("123456789", cb)
	s.OnSelectProtocolAck(1) // builds mlsClient

	// Set an arbitrary groupID (not present in the store) to pass the
	// handler's group check. With 0 refs, processRevokeProposalsLocked
	// returns nil before touching the client, so the group doesn't need to
	// actually exist.
	s.mu.Lock()
	s.groupID = []byte("group-X")
	s.mu.Unlock()

	// Reset counters after setup (OnSelectProtocolAck sends a key package but no commit).
	cb.mu.Lock()
	cb.commits = 0
	cb.mu.Unlock()

	// Revoke batch with 0 refs (success/no-op path). The handler must reach
	// the early return in processAndCommitProposalBatchLocked without
	// invoking a commit.
	batch := buildRevokeBatch(nil)
	s.OnDaveMLSProposals(batch)

	cb.mu.Lock()
	got := cb.commits
	cb.mu.Unlock()
	if got != 0 {
		t.Errorf("OnDaveMLSProposals(revoke) invoked SendMLSCommitWelcome %d times; want 0 (revoke doesn't commit)", got)
	}
}

type commitCountingCallbacks struct {
	mu          sync.Mutex
	keyPackages [][]byte
	commits     int
}

func (c *commitCountingCallbacks) SendMLSKeyPackage(kp []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages = append(c.keyPackages, append([]byte(nil), kp...))

	return nil
}

func (c *commitCountingCallbacks) SendMLSCommitWelcome([]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commits++

	return nil
}

func (c *commitCountingCallbacks) SendReadyForTransition(uint16) error   { return nil }
func (c *commitCountingCallbacks) SendInvalidCommitWelcome(uint16) error { return nil }
