package session

import (
	"strings"
	"time"
)

const retryMaxAttempts = 6

// retryDelay is the pause between "shard not ready" attempts.
// Tests can set this to zero to avoid blocking for seconds.
var retryDelay = 200 * time.Millisecond //nolint:gochecknoglobals

// isShardNotReady reports whether err is a transient "shard not ready" from
// the voice gateway — this happens during the brief window after a channel move
// while the WebSocket handshake hasn't completed yet.
func isShardNotReady(err error) bool {
	return err != nil && strings.Contains(err.Error(), "shard is not ready")
}

// retrySend calls fn up to retryMaxAttempts times, sleeping between attempts
// when the shard is not ready. s.mu must be held by the caller; it remains
// held throughout (including during sleeps) so callers don't need to re-validate
// state after each attempt.
func (s *session) retrySend(fn func() error) error {
	for i := range retryMaxAttempts {
		err := fn()
		if err == nil {
			return nil
		}

		if !isShardNotReady(err) || i == retryMaxAttempts-1 {
			return err
		}

		s.logger.Debug("shard not ready, retrying send",
			"attempt", i+1,
			"max_attempts", retryMaxAttempts,
			"retry_delay_ms", retryDelay.Milliseconds())

		time.Sleep(retryDelay)
	}

	return nil
}
