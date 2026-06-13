package session

import "time"

// State is a snapshot of the session's ability to encrypt media.
type State struct {
	// EpochID is the active MLS epoch, 0 when none is active.
	EpochID uint64
	// Ready reports whether Encrypt can currently succeed.
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

// Ready reports whether the session can currently encrypt media frames. It is
// part of the godave.Session interface; AudioSenders call it every frame to
// hold playback while the MLS epoch is being established or recovered.
func (s *session) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.activeEpoch != nil && s.sendRatchet != nil
}
