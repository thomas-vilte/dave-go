package session

import (
	"context"
	"io"
)

// The session's lifecycle teardown is exposed as io.Closer so voice layers
// that only know the session as a godave.Session can tear it down with a
// plain `if c, ok := sess.(io.Closer); ok { c.Close() }`.
var _ io.Closer = (*Session)(nil)

// Close cancels the session's internal context so the recovery and
// commit-confirm watchdogs exit promptly. Call it when discarding the
// session (channel move, voice disconnect). It is fire-and-forget: it
// returns immediately and does NOT wait for in-flight watchdogs to finish
// (use WaitShutdown for that). Idempotent — safe to call multiple times.
// It never fails; the error return exists to satisfy io.Closer and is
// always nil.
//
// Forgetting to call Close is not a permanent leak — the recovery watchdog
// re-arms at most maxRecoveryAttempts times, waiting recoveryTimeout per
// attempt (3 × 15s ≈ 45s worst case), then exits on its own — but during
// that window the stale session keeps re-arming invalidations, polluting
// logs and risking a "full voice reconnect required" on a channel the bot
// no longer occupies.
func (s *Session) Close() error {
	s.shutdownOnce.Do(func() {
		s.watchdogMu.Lock()
		s.shutdownCancel()
		s.watchdogMu.Unlock()
		go func() {
			s.watchdogs.Wait()
			close(s.shutdownDone)
		}()
	})

	return nil
}

// WaitShutdown blocks until every watchdog spawned before Close() has
// exited, or ctx is done. Use this on orderly process shutdown if you need
// a guarantee that no dave-go goroutine outlives the program. A watchdog
// that is firing holds the session lock while it calls the callbacks, so
// calling this from a callback, or while holding a lock the callbacks need,
// can block until ctx is done.
func (s *Session) WaitShutdown(ctx context.Context) error {
	select {
	case <-s.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// goWatchdog runs watchdog on a goroutine that WaitShutdown waits for. It
// does nothing once Close has been called, so no Add can race the Wait.
func (s *Session) goWatchdog(watchdog func()) {
	s.watchdogMu.Lock()
	defer s.watchdogMu.Unlock()
	if s.shutdownCtx.Err() != nil {
		return
	}
	s.watchdogs.Go(watchdog)
}
