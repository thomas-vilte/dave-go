package session

import (
	"testing"
	"time"
)

// TestCommitRecovery_ArmsAfterSoleMemberActivation reproduces the leave/rejoin
// failure seen in interop: a sole-member activation closes epochReady (via
// signalEpochReadyLocked), and a subsequent commit for a re-joining member must
// still arm its recovery watchdog. Before the fix, commitProposalsLocked read
// the already-closed epochReady, so the watchdog returned immediately and the
// session could get stuck at the sole-member epoch forever with no self-heal.
// After the fix, commitProposalsLocked resets epochReady first, so the watchdog
// waits for THIS commit's activation and fires recovery on timeout.
func TestCommitRecovery_ArmsAfterSoleMemberActivation(t *testing.T) {
	cb := &countingCallbacks{}
	pkg, extPriv := buildExternalSenderPackageWithKey(t)

	s := New(nil, "123456789", cb).(*session)
	s.recoveryTimeout = 20 * time.Millisecond
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(pkg)
	s.OnDavePrepareTransition(0, 1) // sole-member reset → activates → closes epochReady

	// Precondition for the bug: the sole-member activation left epochReady closed.
	s.mu.RLock()
	closed := false
	select {
	case <-s.epochReady:
		closed = true
	default:
	}
	s.mu.RUnlock()
	if !closed {
		t.Fatal("expected epochReady to be closed after sole-member activation")
	}

	// A member re-joins: a real external-sender add proposal is committed, which
	// creates a pending epoch and arms the recovery watchdog. We never deliver
	// execute_transition (op22), so the transition never activates — recovery
	// MUST fire (this is exactly the stuck-forever case from the interop log).
	const joiner = "222222222"
	s.AddUser(joiner)
	proposalBytes := addProposalBytesForUser(t, s, extPriv, joiner)
	s.OnDaveMLSProposals(buildProposalBatch(proposalBytes))

	eventually(t, func() bool {
		invalidCommits, _ := cb.counts()

		return invalidCommits > 0
	}, "recovery watchdog should fire SendInvalidCommitWelcome after the timeout (was dead-on-arrival on a closed epochReady)")
}
