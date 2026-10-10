package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"github.com/thomas-vilte/dave-go/mediakeys"
	"github.com/thomas-vilte/mls-go/group"
)

func TestSessionLoggerCarriesCorrelationFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	s := New("user-1", &kpCapturingCallbacks{}, WithLogger(logger))

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
	s := New("user-1", &kpCapturingCallbacks{}, WithLogger(logger))

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

// containsSecretBytes reports whether logs holds any 6-byte run of secret in
// hex, so a match doesn't depend on which slice of it a log line printed.
func containsSecretBytes(logs string, secret []byte) bool {
	const window = 6
	for i := 0; i+window <= len(secret); i++ {
		if strings.Contains(strings.ToLower(logs), hex.EncodeToString(secret[i:i+window])) {
			return true
		}
	}

	return false
}

func TestDebugLogsCarryNoKeyMaterial(t *testing.T) {
	var defaultLogs, sessionLogs bytes.Buffer
	debug := &slog.HandlerOptions{Level: slog.LevelDebug}
	// slog.Default is process-wide, so this test must not run in parallel
	// with anything else that logs through it.
	oldDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&defaultLogs, debug)))
	t.Cleanup(func() { slog.SetDefault(oldDefault) })

	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb, WithLogger(slog.New(slog.NewTextHandler(&sessionLogs, debug))))
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	externalSenderPackage := buildExternalSenderPackage(t)
	s.OnDaveMLSExternalSenderPackage(externalSenderPackage)
	_, welcome := newWelcomeForExternalSender(t, cb.lastKeyPackage(), externalSenderPackage)
	// The peer that built the Welcome logs through slog.Default; only the bot's
	// own lines are under test.
	defaultLogs.Reset()
	s.OnDaveMLSWelcome(0, welcome)
	if !s.State().Ready {
		t.Fatal("State().Ready should be true once the Welcome's epoch is active")
	}

	s.mu.RLock()
	store, groupID := s.mlsClient.store, s.groupID
	s.mu.RUnlock()
	raw, err := store.LoadGroupState(context.Background(), group.NewGroupID(groupID))
	if err != nil {
		t.Fatalf("LoadGroupState: %v", err)
	}
	state, err := group.UnmarshalGroupState(raw)
	if err != nil {
		t.Fatalf("UnmarshalGroupState: %v", err)
	}
	baseSecret, err := mediakeys.DeriveSenderBaseSecret(exporterAdapter{store: store, groupID: groupID}, 123456789)
	if err != nil {
		t.Fatalf("DeriveSenderBaseSecret: %v", err)
	}
	ratchet, err := mediakeys.NewKeyRatchet(baseSecret)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	generationZeroKey, err := ratchet.GetKey(0)
	if err != nil {
		t.Fatalf("GetKey(0): %v", err)
	}

	secrets := map[string][]byte{
		"sender base secret":  baseSecret,
		"generation 0 key":    generationZeroKey,
		"MLS exporter secret": state.EpochSecrets().ExporterSecret.AsSlice(),
	}
	for name, secret := range secrets {
		if containsSecretBytes(sessionLogs.String(), secret) {
			t.Errorf("session logger output contains bytes of the %s", name)
		}
	}
	if !strings.Contains(sessionLogs.String(), `msg="joined group"`) {
		t.Error("mls-go's join was not logged through the session logger")
	}
	if defaultLogs.Len() != 0 {
		t.Errorf("logged through slog.Default instead of the session logger:\n%s", defaultLogs.String())
	}
}
