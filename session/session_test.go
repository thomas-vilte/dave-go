package session

import (
	"testing"

	"github.com/disgoorg/godave"
)

type testCallbacks struct{}

func (testCallbacks) SendMLSKeyPackage([]byte) error        { return nil }
func (testCallbacks) SendMLSCommitWelcome([]byte) error     { return nil }
func (testCallbacks) SendReadyForTransition(uint16) error   { return nil }
func (testCallbacks) SendInvalidCommitWelcome(uint16) error { return nil }

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

func TestEncryptNoActiveEpoch(t *testing.T) {
	s := New(nil, "test_user", testCallbacks{})
	sess := s.(*session)
	sess.sendCounter.Next()

	_, err := sess.Encrypt(12345, []byte{0x01, 0x02}, make([]byte, 256))
	if err == nil {
		t.Fatal("expected error when no active epoch")
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
