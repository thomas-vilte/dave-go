package session

import "time"

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
}

// Stats are cumulative counters since the session was created.
type Stats struct {
	CommitsProcessed uint64
	CommitsFailed    uint64
	WelcomesJoined   uint64
	WelcomesFailed   uint64
	RecoveryAttempts uint64
	EncryptFailures  uint64
	// PassthroughFrames counts frames forwarded unmodified because no E2EE epoch
	// was active (sole member before activation, or a protocol-version-0 session).
	PassthroughFrames uint64
}

// Reporter is implemented by sessions created with New. Integrators can
// type-assert the godave.Session to observe session health and export it
// with their own metrics stack; the library takes no telemetry dependency.
type Reporter interface {
	State() State
	Stats() Stats
}

var _ Reporter = (*session)(nil)

func (s *session) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := State{
		Ready:         s.activeEpoch != nil && s.sendRatchet != nil,
		DegradedSince: s.degradedSince,
	}
	if s.activeEpoch != nil {
		st.EpochID = s.activeEpoch.id
	}

	return st
}

func (s *session) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.stats
}

// Ready reports whether the session can accept frames for Encrypt. It always
// returns true: Encrypt never fails for lack of an epoch, it falls back to
// passthrough so the audio stream keeps advancing even when the bot is alone or
// mid-transition (per the DAVE spec, a sole member should still advance its
// stream). Integrators that want to know whether frames are actually end-to-end
// encrypted should read State (EpochID/Ready) rather than gate playback here.
func (s *session) Ready() bool {
	return true
}
