package session

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
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
