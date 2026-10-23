package session

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
)

func TestEncrypt_StrictWithoutSendKey(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		steps   func(s *Session)
		wantErr bool
	}{
		{name: "strict before negotiation", opts: []Option{WithStrictEncrypt()}, steps: func(*Session) {}},
		{name: "strict at version 0", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) { s.OnSelectProtocolAck(0) }},
		{name: "strict during the handshake", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) { s.OnSelectProtocolAck(1) }, wantErr: true},
		{name: "strict upgrading, prepare_transition only", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) {
			s.OnSelectProtocolAck(0)
			s.OnDavePrepareTransition(5, 1)
		}},
		{name: "strict upgrading, prepare_epoch only", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) {
			s.OnSelectProtocolAck(0)
			s.OnDavePrepareEpoch(1, 1)
		}},
		{name: "strict upgrading, prepare_epoch then prepare_transition", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) {
			s.OnSelectProtocolAck(0)
			s.OnDavePrepareEpoch(1, 1)
			s.OnDavePrepareTransition(5, 1)
		}},
		{name: "strict after a downgrade executes", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) {
			s.OnSelectProtocolAck(1)
			s.OnDavePrepareTransition(5, 0)
			s.OnDaveExecuteTransition(5)
		}},
		{name: "strict upgrading again after a downgrade", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) {
			s.OnSelectProtocolAck(1)
			s.OnDavePrepareTransition(5, 0)
			s.OnDaveExecuteTransition(5)
			s.OnDavePrepareEpoch(1, 1)
		}},
		{name: "strict after transition 0 without an external sender", opts: []Option{WithStrictEncrypt()}, steps: func(s *Session) {
			s.OnSelectProtocolAck(0)
			s.OnDavePrepareEpoch(1, 1)
			s.OnDavePrepareTransition(0, 1)
		}, wantErr: true},
		{name: "default during the handshake", steps: func(s *Session) { s.OnSelectProtocolAck(1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New("123456789", testCallbacks{}, tt.opts...)
			closeAtCleanup(t, s)
			tt.steps(s)

			plaintext := []byte("audio")
			out := make([]byte, s.MaxEncryptedFrameSize(len(plaintext)))
			n, err := s.Encrypt(1, plaintext, out)
			stats := s.Stats()
			if !tt.wantErr {
				if err != nil || !bytes.Equal(out[:n], plaintext) || stats.PassthroughFrames != 1 {
					t.Fatalf("Encrypt = %x, %v, PassthroughFrames %d; want passthrough", out[:n], err, stats.PassthroughFrames)
				}

				return
			}
			if !errors.Is(err, ErrMissingKeyRatchet) {
				t.Fatalf("Encrypt error = %v, want ErrMissingKeyRatchet", err)
			}
			if stats.EncryptFailures != 1 || stats.PassthroughFrames != 0 {
				t.Fatalf("EncryptFailures = %d, PassthroughFrames = %d, want 1 and 0", stats.EncryptFailures, stats.PassthroughFrames)
			}
		})
	}
}

func TestEncrypt_StrictAfterResetRetention(t *testing.T) {
	s := New("123456789", testCallbacks{}, WithStrictEncrypt())
	closeAtCleanup(t, s)
	s.sendRetentionTTL = 50 * time.Millisecond
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.OnDavePrepareTransition(0, 1)
	s.OnDavePrepareEpoch(1, 1)

	plaintext := []byte("audio")
	out := make([]byte, s.MaxEncryptedFrameSize(len(plaintext)))
	n, err := s.Encrypt(1, plaintext, out)
	if err != nil || !frame.LooksLikeDAVEFrame(out[:n]) {
		t.Fatalf("Encrypt within the retention = %x, %v; want a DAVE frame", out[:n], err)
	}
	time.Sleep(2 * s.sendRetentionTTL)
	if _, err := s.Encrypt(1, plaintext, out); !errors.Is(err, ErrMissingKeyRatchet) {
		t.Fatalf("Encrypt after the retention: error = %v, want ErrMissingKeyRatchet", err)
	}
}

func TestEncrypt_StrictAfterActivationWithoutUs(t *testing.T) {
	s := setupForActivation(t, []godave.UserID{"bot"}, []godave.UserID{"other"})
	s.strictEncrypt = true
	s.mu.Lock()
	s.protocolVersion = 1
	s.activatePendingEpochLocked()
	s.mu.Unlock()

	if _, err := s.Encrypt(1, []byte("audio"), make([]byte, 64)); !errors.Is(err, ErrMissingKeyRatchet) {
		t.Fatalf("Encrypt error = %v, want ErrMissingKeyRatchet", err)
	}
}

func TestEncrypt_StrictAfterSoleMemberUpgrade(t *testing.T) {
	s := New("123456789", testCallbacks{}, WithStrictEncrypt())
	closeAtCleanup(t, s)
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(0)
	s.OnDavePrepareEpoch(1, 1)
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.OnDavePrepareTransition(0, 1)

	plaintext := []byte("audio")
	out := make([]byte, s.MaxEncryptedFrameSize(len(plaintext)))
	n, err := s.Encrypt(1, plaintext, out)
	if err != nil || !frame.LooksLikeDAVEFrame(out[:n]) {
		t.Fatalf("Encrypt after the upgrade = %x, %v; want a DAVE frame", out[:n], err)
	}
}
