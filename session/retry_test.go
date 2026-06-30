package session

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func init() {
	// Tests override retryDelay to zero so they don't wait 1+ second.
	retryDelay = 0
}

func newTestSession() *session {
	return New(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), "user-1", &kpCapturingCallbacks{}).(*session)
}

func TestRetrySend_SucceedsOnFirstAttempt(t *testing.T) {
	s := newTestSession()
	s.mu.Lock()
	defer s.mu.Unlock()

	calls := 0
	err := s.retrySend(func() error {
		calls++

		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRetrySend_RetriesOnShardNotReady(t *testing.T) {
	s := newTestSession()
	s.mu.Lock()
	defer s.mu.Unlock()

	shardErr := errors.New("shard is not ready")
	calls := 0

	err := s.retrySend(func() error {
		calls++
		if calls < 3 {
			return shardErr
		}

		return nil
	})
	if err != nil {
		t.Fatalf("expected nil after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetrySend_GivesUpAfterMaxAttempts(t *testing.T) {
	s := newTestSession()
	s.mu.Lock()
	defer s.mu.Unlock()

	shardErr := errors.New("shard is not ready")
	calls := 0

	err := s.retrySend(func() error {
		calls++

		return shardErr
	})
	if !errors.Is(err, shardErr) {
		t.Fatalf("expected shardErr, got %v", err)
	}
	if calls != retryMaxAttempts {
		t.Fatalf("expected %d calls, got %d", retryMaxAttempts, calls)
	}
}

func TestRetrySend_DoesNotRetryOnOtherErrors(t *testing.T) {
	s := newTestSession()
	s.mu.Lock()
	defer s.mu.Unlock()

	otherErr := errors.New("some other error")
	calls := 0

	err := s.retrySend(func() error {
		calls++

		return otherErr
	})
	if !errors.Is(err, otherErr) {
		t.Fatalf("expected otherErr, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (no retry), got %d", calls)
	}
}

func TestIsShardNotReady(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"shard is not ready", true},
		{"send mls key package: shard is not ready", true},
		{"some other error", false},
		{"", false},
	}

	for _, tc := range cases {
		var err error
		if tc.msg != "" {
			err = errors.New(tc.msg)
		}

		got := isShardNotReady(err)
		if got != tc.want {
			t.Errorf("isShardNotReady(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// TestRetrySend_HonorsClose verifies that calling Close during a retry
// causes the in-progress retrySend to exit early with the context
// error instead of waiting for the full backoff to elapse.
func TestRetrySend_HonorsClose(t *testing.T) {
	// Use a non-zero delay so the retrySend goroutine is actually inside
	// the interruptible select when Close arrives. The init() override
	// sets retryDelay=0 globally which would make the timer fire before
	// Close has a chance to cancel it.
	origDelay := retryDelay
	retryDelay = 200 * time.Millisecond
	defer func() { retryDelay = origDelay }()

	s := newTestSession()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Run retrySend in a goroutine. The function always returns
	// "shard not ready" so the retry would otherwise cycle through the
	// full backoff schedule (~12.5s with production defaults).
	done := make(chan error, 1)
	go func() {
		done <- s.retrySend(func() error {
			return errors.New("shard is not ready")
		})
	}()

	// Give the goroutine a moment to enter the first sleep.
	time.Sleep(20 * time.Millisecond)

	// Close should cancel shutdownCtx and unblock the sleep.
	s.Close()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retrySend did not exit within 1s after Close")
	}
}

// TestRetrySend_ExponentialBackoff verifies the per-attempt delay doubles
// up to the cap. With retryDelay=50ms and retryMaxDelay=200ms, the
// expected schedule is [50, 100, 200, 200, 200]ms = 750ms minimum for
// 5 delays between 6 attempts.
func TestRetrySend_ExponentialBackoff(t *testing.T) {
	origDelay, origMax := retryDelay, retryMaxDelay
	retryDelay = 50 * time.Millisecond
	retryMaxDelay = 200 * time.Millisecond
	defer func() {
		retryDelay = origDelay
		retryMaxDelay = origMax
	}()

	s := newTestSession()
	s.mu.Lock()
	defer s.mu.Unlock()

	start := time.Now()
	err := s.retrySend(func() error {
		return errors.New("shard is not ready")
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from exhausted retries")
	}
	if elapsed < 750*time.Millisecond {
		t.Fatalf("backoff too fast: %v (expected >= 750ms)", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("backoff too slow: %v (expected < 2s)", elapsed)
	}
}
