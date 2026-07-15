package session

import (
	"context"
	"time"
)

// State is a snapshot of the session's ability to encrypt media.
type State struct {
	// EpochID is the active MLS epoch, 0 when none is active.
	EpochID uint64
	// Ready reports whether frames are currently end-to-end encrypted. It is
	// false while the session is in passthrough (no active epoch), e.g. a sole
	// member before its epoch activates or a protocol-version-0 session.
	Ready bool
	// DegradedSince is when the session lost its epoch (zero while Ready,
	// or if the session never degraded). Integrators can use it to stop
	// sending frames or force a full voice reconnect after a threshold.
	DegradedSince time.Time
	// ProtocolVersion is the DAVE protocol version reported by the voice
	// gateway via SELECT_PROTOCOL_ACK, PREPARE_EPOCH or PREPARE_TRANSITION.
	// 0 means transport-only: this channel will never have E2EE and Ready
	// will stay false. >0 plus !Ready means a transient MLS handshake
	// window. Use it to tell "hold frames while handshake completes" apart
	// from "no E2EE; passthrough forever" without blocking the audio
	// sender indefinitely.
	ProtocolVersion uint16
}

// Stats are cumulative counters since the session was created.
type Stats struct {
	CommitsProcessed uint64
	CommitsFailed    uint64
	WelcomesJoined   uint64
	WelcomesFailed   uint64
	// RecoveryAttempts counts recoveries armed by a real MLS fault (invalid
	// commit/welcome) — see watchRecoveryLocked. Transport-induced skips
	// (voice gateway down, "shard is not ready") increment
	// RecoveryAttemptsTransport instead, so an integrator can separate
	// Discord-side MLS faults from network blips without parsing logs.
	RecoveryAttempts uint64
	// RecoveryAttemptsTransport counts the number of times a recovery was
	// skipped because the voice gateway was transiently down ("shard is not
	// ready"). Distinct from RecoveryAttempts, which only counts MLS faults.
	RecoveryAttemptsTransport uint64
	EncryptFailures           uint64
	// DecryptFailures counts Decrypt calls that returned an error: plaintext
	// injected under active E2EE, malformed DAVE frames, and frames that no
	// known epoch/sender key could authenticate. Sporadic bursts right after
	// a join/move are protocol-normal (frames encrypted for an epoch this
	// session was never a member of — it cannot have those keys); sustained
	// growth outside transition windows means a diverged peer or an
	// injection attempt. Frames rejected as replays are included here too
	// (they also increment RejectedReplayFrames, which is the breakdown).
	DecryptFailures uint64
	// PassthroughFrames counts frames forwarded unmodified because no E2EE epoch
	// was active (sole member before activation, or a protocol-version-0 session).
	PassthroughFrames uint64
	// TransitionFrames counts frames encrypted with the retained (previous) send
	// ratchet during the post-activation transition window. Non-zero means the
	// session activated a new epoch and the receiver might still be on the
	// previous one. Useful for observability and to confirm the
	// post-activation bridge is doing its job in production.
	TransitionFrames uint64
	// TransitionWindows counts distinct post-activation retention windows
	// entered by this session (one per epoch activation that had a previous send
	// ratchet to retain). Complements TransitionFrames: the retention TTL is a
	// fixed constant (sendRetentionTTL), so "total time in transition" would be
	// TransitionWindows * sendRetentionTTL — redundant. A window with zero
	// TransitionFrames is still informative (epoch activated without any frame
	// emitted in the gap); a window with many TransitionFrames confirms jitter
	// on execute_transition delivery.
	TransitionWindows uint64
	// DegradedDuration accumulates time spent in degraded state (no active
	// E2EE epoch) across all recovery cycles that ended in
	// markRecoveredLocked. Gaps that end when the session is closed without
	// recovery are NOT counted — only recoveries that succeeded. Reflects the
	// duration of MLS-induced outages the session actually fixed on its own.
	DegradedDuration time.Duration
	// TransportRetryDuration accumulates the wall-clock time this session
	// spent inside retrySend backoff loops caused by "shard is not ready"
	// (voice gateway transiently down), across every call site that uses
	// retrySend (key package, commit/welcome, ready-for-transition sends).
	// Counted whether the retry eventually succeeded, exhausted its attempts,
	// or was cut short by Close(). Unlike RecoveryAttemptsTransport (a count
	// of skipped recoveries), this answers "how long was the gateway down,
	// from this session's point of view" — useful to distinguish a brief
	// blip from a prolonged outage without grepping DEBUG logs.
	TransportRetryDuration time.Duration
	// RejectedReplayFrames counts frames that were rejected because the
	// expanded nonce had already been seen in the current epoch.
	// A non-zero value indicates a replay attack or a network duplicate that
	// survived long enough to reach the decryptor after a prior successful
	// decryption.
	RejectedReplayFrames uint64
	// ProposalsRejected counts MLS proposals refused by the DAVE validation
	// layer before reaching the MLS client: disallowed sender or proposal
	// type (only Add/Remove from the voice gateway's external sender are
	// allowed, protocol.md "Proposal Handling"), add proposals for users not
	// expected in the session, and proposals that failed safe inspection
	// (fail-closed). Zero in normal operation; growth means the gateway is
	// sending malformed batches or something is probing the session with
	// crafted proposals — i.e. the validation layer actively doing its job.
	ProposalsRejected uint64
	// DowngradeToV0 counts the number of times the session was downgraded
	// from DAVE E2EE (protocol version ≥ 1) to transport-only encryption
	// (protocol version 0). Non-zero indicates the call received at least
	// one non-supporting client.
	DowngradeToV0 uint64
}

// State returns a point-in-time snapshot of the session's E2EE state. Use it
// to observe session health and export it with your own metrics stack; the
// library takes no telemetry dependency.
func (s *Session) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := State{
		Ready:           s.activeEpoch != nil && s.sendRatchet != nil,
		DegradedSince:   s.degradedSince,
		ProtocolVersion: s.protocolVersion,
	}
	if s.activeEpoch != nil {
		st.EpochID = s.activeEpoch.id
	}

	return st
}

// Stats returns the session's cumulative counters. See the Stats type for
// what each field measures.
func (s *Session) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.stats
}

// Ready reports whether the session has an active E2EE epoch and can encrypt
// frames. Returns false during the MLS handshake window so audio senders can
// hold frames until encryption is established. Returns true when the bot is
// alone (sole-member epoch active) or when a multi-member epoch is ready.
// Encrypt never errors regardless — it falls back to passthrough — so callers
// that don't gate on Ready still work correctly.
//
// Equivalent signals: State().Ready is the same boolean as a point-in-time
// snapshot, and WaitReady(ctx) blocks until the first time it becomes true.
// The noop session returned by godave.NewNoopSession makes Ready always
// return true.
//
// To tell "handshake in progress, expect E2EE soon" apart from "this channel
// will never have E2EE", check State().ProtocolVersion. 0 means no E2EE will
// be established on this channel (Ready stays false forever); >0 with !Ready
// means a transient handshake window. Audio senders should prefer
// ShouldHoldFrames, which encodes that distinction.
func (s *Session) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.activeEpoch != nil && s.sendRatchet != nil
}

// ShouldHoldFrames reports whether an audio sender should hold (not send)
// frames right now: true only during a transient E2EE handshake window —
// encryption is expected but not yet established. It returns false both when
// the session is ready to encrypt and when the channel will never have E2EE
// (transport-only, protocol version 0), so gating on it never stalls a
// sender forever. Frames sent while it returns true would go out in
// passthrough (unencrypted) and be dropped by receivers expecting E2EE.
func (s *Session) ShouldHoldFrames() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ready := s.activeEpoch != nil && s.sendRatchet != nil

	return !ready && s.protocolVersion != 0
}

// WaitReady blocks without polling until the first E2EE epoch activates or
// ctx is done. The start reference is degradedSince if already set (i.e.
// PrepareEpoch was received before the call), otherwise the moment WaitReady
// is called — so calling it right after New gives an accurate
// first-handshake latency.
//
// The loop is safe against epoch resets: resetEpochReadyLocked closes the old
// channel and replaces it atomically under the write lock, so a spurious wake
// always re-reads a fresh channel on the next iteration rather than spinning.
func (s *Session) WaitReady(ctx context.Context) (time.Duration, error) {
	start := time.Now()

	s.mu.RLock()
	if !s.degradedSince.IsZero() {
		start = s.degradedSince
	}
	s.mu.RUnlock()

	for {
		s.mu.RLock()
		ready := s.activeEpoch != nil && s.sendRatchet != nil
		ch := s.epochReady
		s.mu.RUnlock()

		if ready {
			return time.Since(start), nil
		}

		select {
		case <-ch:
			// Either signalEpochReadyLocked (session ready) or
			// resetEpochReadyLocked (new epoch starting) — re-check under lock.
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}
