package session

import (
	"strings"
	"time"
)

const retryBackoffFactor = 2.0

var (
	// retryDelay is the initial delay between attempts. Doubles per
	// attempt up to retryMaxDelay. Total worst-case window is bounded
	// by the sum of the backoff schedule (~12.5s with the defaults).
	// Tests override to 0 to keep retry tests instant.
	retryDelay = 500 * time.Millisecond //nolint:gochecknoglobals
	// retryMaxDelay caps the per-attempt delay so a long gateway
	// outage doesn't push the retry window into the tens of seconds.
	retryMaxDelay = 5 * time.Second //nolint:gochecknoglobals
	// retryMaxAttempts is the total number of send attempts (including
	// the first one) before giving up.
	retryMaxAttempts = 6 //nolint:gochecknoglobals
)

// isShardNotReady reports whether err is a transient "shard not ready" from
// the voice gateway — this happens during the brief window after a channel move
// while the WebSocket handshake hasn't completed yet.
func isShardNotReady(err error) bool {
	return err != nil && strings.Contains(err.Error(), "shard is not ready")
}

// retrySend calls fn up to retryMaxAttempts times, doubling the wait
// between attempts (capped at retryMaxDelay) when the shard is not
// ready. The sleep is interruptible: if the session is closed (via
// Closer.Close) the retry exits early with the context error so
// shutdown doesn't have to wait for the full backoff to finish.
//
// s.mu must be held by the caller; it remains held throughout (including
// during sleeps) so callers don't need to re-validate state after each attempt.
func (s *session) retrySend(fn func() error) error {
	delay := retryDelay

	// retryStart is set the first time we decide to retry (i.e. the first
	// "shard is not ready" failure), not at function entry — a single fn()
	// call's own latency isn't gateway downtime. Accumulated into
	// Stats.TransportRetryDuration on every exit path (success, exhausted
	// attempts, or Close() interruption) via defer so there's one place
	// that does the bookkeeping regardless of how the loop ends.
	var retryStart time.Time

	defer func() {
		if !retryStart.IsZero() {
			s.stats.TransportRetryDuration += time.Since(retryStart)
		}
	}()

	for i := range retryMaxAttempts {
		err := fn()
		if err == nil {
			return nil
		}

		if !isShardNotReady(err) || i == retryMaxAttempts-1 {
			return err
		}

		if retryStart.IsZero() {
			retryStart = time.Now()
		}

		s.logger.Debug("shard not ready, retrying send",
			"attempt", i+1,
			"max_attempts", retryMaxAttempts,
			"delay_ms", delay.Milliseconds())

		// Interruptible sleep: bail out if the session is closed.
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-s.shutdownCtx.Done():
			timer.Stop()

			return s.shutdownCtx.Err()
		}

		// Exponential backoff with cap.
		delay = min(time.Duration(float64(delay)*retryBackoffFactor), retryMaxDelay)
	}

	return nil
}
