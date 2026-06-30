package session

import "context"

// Closer exposes the lifecycle hook for a DAVE session. Integrators MUST
// call Close() when they discard a session (channel move, voice
// disconnect) so the recovery and commit-confirm watchdogs exit
// promptly. Without it, the old session keeps re-arming invalidations
// for up to 15s after the move and pollutes logs / risks "full voice
// reconnect required" on a channel the bot no longer occupies.
type Closer interface {
	// Close cancels the session's internal context. It is fire-and-forget:
	// it returns immediately and does NOT wait for in-flight watchdogs
	// to finish. Idempotent — safe to call multiple times.
	Close()

	// WaitShutdown blocks until every watchdog spawned before Close()
	// has exited, or ctx is done. Use this on orderly process shutdown
	// if you need a guarantee that no dave-go goroutine outlives the
	// program.
	WaitShutdown(ctx context.Context) error
}

var _ Closer = (*session)(nil)

// Close implements Closer. see type docs.
func (s *session) Close() {
	s.shutdownOnce.Do(func() {
		s.shutdownCancel()
		close(s.shutdownDone)
	})
}

// WaitShutdown implements Closer. see type docs.
func (s *session) WaitShutdown(ctx context.Context) error {
	select {
	case <-s.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
