package session

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestSessionLoggerCarriesCorrelationFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	s := New(logger, "user-1", &kpCapturingCallbacks{}).(*session)

	s.logger.Info("before channel")
	first := buf.String()
	if !strings.Contains(first, `"dave_session"`) {
		t.Errorf("missing dave_session before channel:\n%s", first)
	}
	if !strings.Contains(first, `"user_id":"user-1"`) {
		t.Errorf("missing user_id before channel:\n%s", first)
	}
	if strings.Contains(first, "channel_id") {
		t.Errorf("channel_id should not be set before SetChannelID:\n%s", first)
	}

	buf.Reset()
	s.SetChannelID(1234567890)
	s.logger.Info("after channel")
	second := buf.String()
	for _, want := range []string{`"dave_session"`, `"user_id":"user-1"`, `"channel_id":1234567890`} {
		if !strings.Contains(second, want) {
			t.Errorf("missing %s after SetChannelID:\n%s", want, second)
		}
	}
}

func TestMarkDegraded_LogsTransitionOnce(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	s := New(logger, "user-1", &kpCapturingCallbacks{}).(*session)

	s.markDegradedLocked("first reason", "epoch_id", uint64(5))
	s.markDegradedLocked("second reason")

	out := buf.String()
	if n := strings.Count(out, "session entering degraded state"); n != 1 {
		t.Errorf("expected degraded transition logged once, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "first reason") {
		t.Errorf("missing reason on degraded log:\n%s", out)
	}
	if strings.Contains(out, "second reason") {
		t.Errorf("re-entry should not log:\n%s", out)
	}

	buf.Reset()
	s.markRecoveredLocked(7)
	rec := buf.String()
	if !strings.Contains(rec, "session recovered") || !strings.Contains(rec, `"epoch_id":7`) {
		t.Errorf("expected recovery log with epoch_id:\n%s", rec)
	}

	buf.Reset()
	s.markRecoveredLocked(8)
	if buf.Len() != 0 {
		t.Errorf("recovery without prior degraded should be a no-op, got:\n%s", buf.String())
	}
}

func TestNewSessionID_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		id := newSessionID()
		if id == "" {
			t.Fatal("empty session id")
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate session id: %s", id)
		}
		seen[id] = struct{}{}
	}
}
