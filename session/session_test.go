package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/mediakeys"
)

type testCallbacks struct{}

func (testCallbacks) SendMLSKeyPackage([]byte) error        { return nil }
func (testCallbacks) SendMLSCommitWelcome([]byte) error     { return nil }
func (testCallbacks) SendReadyForTransition(uint16) error   { return nil }
func (testCallbacks) SendInvalidCommitWelcome(uint16) error { return nil }

// TestNewWithReporter verifies the create func hands the integrator a working
// Reporter AND a Closer via the closure, so they don't have to type-assert
// the godave.Session to grab either.
func TestNewWithReporter(t *testing.T) {
	cb := testCallbacks{}
	var gotReporter Reporter

	createFunc := NewWithReporter(func(r Reporter, _ Closer, _ godave.Callbacks) {
		gotReporter = r
	})

	s := createFunc(nil, "123456789", cb)
	if s == nil {
		t.Fatal("NewWithReporter create func returned nil")
	}
	if gotReporter == nil {
		t.Fatal("reporter callback was not invoked with a Reporter")
	}
	if gotReporter.State().Ready {
		t.Fatal("a fresh session should not report E2EE-ready")
	}

	// A nil report func must not panic.
	if NewWithReporter(nil)(nil, "123456789", cb) == nil {
		t.Fatal("NewWithReporter(nil) create func returned nil")
	}
}

func TestNewSession(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	if s == nil {
		t.Fatal("NewSession returned nil")
	}
	if s.MaxSupportedProtocolVersion() != 1 {
		t.Fatalf("expected protocol version 1, got %d", s.MaxSupportedProtocolVersion())
	}
}

func TestMaxEncryptedFrameSize(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	got := s.MaxEncryptedFrameSize(100)
	if got != 164 {
		t.Fatalf("expected 164, got %d", got)
	}
}

func TestMaxDecryptedFrameSize(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	got := s.MaxDecryptedFrameSize("user1", 200)
	if got != 200 {
		t.Fatalf("expected 200, got %d", got)
	}
}

func TestAssignSsrcToCodec(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	s.AssignSsrcToCodec(12345, godave.CodecOpus)

	sess := s.(*session)
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if kind, ok := sess.ssrcCodecs[12345]; !ok || kind != 1 {
		t.Fatalf("expected CodecOpus for SSRC 12345")
	}
}

func TestAddRemoveUser(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	s.AddUser("user1")
	s.AddUser("user2")

	sess := s.(*session)
	sess.mu.RLock()
	if len(sess.users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(sess.users))
	}
	sess.mu.RUnlock()

	s.RemoveUser("user1")
	sess.mu.RLock()
	if len(sess.users) != 1 {
		t.Fatalf("expected 1 user after remove, got %d", len(sess.users))
	}
	sess.mu.RUnlock()
}

func TestSetChannelID(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	s.SetChannelID(42)

	sess := s.(*session)
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.channelID != 42 {
		t.Fatalf("expected channelID 42, got %d", sess.channelID)
	}
}

func TestOnSelectProtocolAck(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	s.OnSelectProtocolAck(1)

	sess := s.(*session)
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.protocolVersion != 1 {
		t.Fatalf("expected protocol version 1, got %d", sess.protocolVersion)
	}
}

func TestOnDavePrepareTransition(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	s.OnDavePrepareTransition(5, 1)

	sess := s.(*session)
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.pendingTransitionID != 5 {
		t.Fatalf("expected pendingTransitionID 5, got %d", sess.pendingTransitionID)
	}
}

func TestOnDaveExecuteTransitionNoPendingEpoch(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	s.OnDaveExecuteTransition(5)

	sess := s.(*session)
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.activeTransitionID != 5 {
		t.Fatalf("expected activeTransitionID 5, got %d", sess.activeTransitionID)
	}
	if sess.pendingTransitionID != 0 {
		t.Fatalf("expected pendingTransitionID 0, got %d", sess.pendingTransitionID)
	}
}

func TestOnDavePrepareEpochReset(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	sess := s.(*session)

	sess.activeEpoch = &epochState{id: 99}
	sess.pendingEpoch = &epochState{id: 100}

	s.OnDavePrepareEpoch(1, 1)

	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.activeEpoch != nil {
		t.Fatal("expected activeEpoch nil after epoch=1")
	}
	if sess.pendingEpoch != nil {
		t.Fatal("expected pendingEpoch nil after epoch=1")
	}
}

// TestEncryptNoActiveEpochPassesThrough verifies that with no active epoch the
// frame is forwarded unmodified (passthrough) instead of failing, so the audio
// stream keeps advancing when the bot is alone or mid-transition.
func TestEncryptNoActiveEpochPassesThrough(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	sess := s.(*session)

	plaintext := []byte{0x01, 0x02, 0x03, 0x04}
	out := make([]byte, 256)
	n, err := sess.Encrypt(12345, plaintext, out)
	if err != nil {
		t.Fatalf("expected passthrough, got error: %v", err)
	}
	if n != len(plaintext) {
		t.Fatalf("passthrough wrote %d bytes, want %d", n, len(plaintext))
	}
	if !bytes.Equal(out[:n], plaintext) {
		t.Fatalf("passthrough altered the frame: got %x, want %x", out[:n], plaintext)
	}
	if got := sess.Stats().PassthroughFrames; got != 1 {
		t.Fatalf("PassthroughFrames = %d, want 1", got)
	}
	if sess.State().Ready {
		t.Fatal("State().Ready should be false while in passthrough")
	}
}

func TestWaitReadyContextCanceled(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.(Reporter).WaitReady(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWaitReadyAlreadyReady(t *testing.T) {
	sess := New(nil, "test_user", testCallbacks{}).(*session)

	sess.mu.Lock()
	sess.activeEpoch = &epochState{id: 1, senders: make(map[godave.UserID]*senderState)}
	var ratchet mediakeys.KeyRatchet
	sess.sendRatchet = &ratchet
	sess.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	d, err := sess.WaitReady(ctx)
	if err != nil {
		t.Fatalf("WaitReady returned unexpected error: %v", err)
	}
	if d > time.Millisecond {
		t.Fatalf("expected near-zero duration when already ready, got %v", d)
	}
}

func TestWaitReadySignaled(t *testing.T) {
	sess := New(nil, "test_user", testCallbacks{}).(*session)

	ready := make(chan time.Duration, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d, _ := sess.WaitReady(ctx)
		ready <- d
	}()

	time.Sleep(10 * time.Millisecond)

	sess.mu.Lock()
	sess.activeEpoch = &epochState{id: 1, senders: make(map[godave.UserID]*senderState)}
	var ratchet mediakeys.KeyRatchet
	sess.sendRatchet = &ratchet
	sess.signalEpochReadyLocked()
	sess.mu.Unlock()

	select {
	case d := <-ready:
		if d <= 0 {
			t.Fatalf("expected positive duration, got %v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitReady did not return after epoch was signaled")
	}
}

func TestWaitReadyEpochReset(t *testing.T) {
	sess := New(nil, "test_user", testCallbacks{}).(*session)

	ready := make(chan time.Duration, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d, _ := sess.WaitReady(ctx)
		ready <- d
	}()

	time.Sleep(10 * time.Millisecond)

	// First: simulate a reset (PrepareEpoch for a new epoch) — goroutine must re-wait.
	sess.mu.Lock()
	sess.resetEpochReadyLocked()
	sess.mu.Unlock()

	select {
	case <-ready:
		t.Fatal("WaitReady returned after reset but before ready")
	case <-time.After(20 * time.Millisecond):
		// good: still waiting
	}

	// Now signal ready.
	sess.mu.Lock()
	sess.activeEpoch = &epochState{id: 2, senders: make(map[godave.UserID]*senderState)}
	var ratchet mediakeys.KeyRatchet
	sess.sendRatchet = &ratchet
	sess.signalEpochReadyLocked()
	sess.mu.Unlock()

	select {
	case d := <-ready:
		if d <= 0 {
			t.Fatalf("expected positive duration after reset+signal, got %v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitReady did not return after reset then signal")
	}
}

func TestDecryptNoActiveEpoch(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})

	// Use a frame that passes LooksLikeDAVEFrame so the epoch check is reached.
	// 11 bytes minimum with 0xFA 0xFA magic marker at the end.
	fakeDAVEFrame := make([]byte, 11)
	fakeDAVEFrame[9] = 0xFA
	fakeDAVEFrame[10] = 0xFA
	_, err := s.Decrypt("user1", fakeDAVEFrame, make([]byte, 256))
	if err == nil {
		t.Fatal("expected error when decrypting with no epoch")
	}
}
