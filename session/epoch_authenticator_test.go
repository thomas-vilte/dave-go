package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
)

// TestEpochAuthenticator_RequiresActiveEpoch verifies that without an active
// MLS epoch both methods return ErrNoActiveEpoch (fresh session case:
// mlsClient and groupID unset).
func TestEpochAuthenticator_RequiresActiveEpoch(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

	if _, err := s.EpochAuthenticator(context.Background()); !errors.Is(err, ErrNoActiveEpoch) {
		t.Fatalf("pre-epoch raw err = %v, want ErrNoActiveEpoch", err)
	}
	if _, err := s.EpochAuthenticatorCode(context.Background()); !errors.Is(err, ErrNoActiveEpoch) {
		t.Fatalf("pre-epoch code err = %v, want ErrNoActiveEpoch", err)
	}
}

// TestEpochAuthenticator_AfterSoleMemberEpoch covers the happy path: after a
// sole-member reset (opcode 25 + transition_id 0) there's an active MLS
// epoch, EpochAuthenticator returns 32 bytes (DHKEMP256 AuthenticationSecret
// ciphersuite), and EpochAuthenticatorCode returns a 30-digit numeric code.
// Reuses the fixture from TestSoleMemberReset_EncryptsWhileAlone.
func TestEpochAuthenticator_AfterSoleMemberEpoch(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	s.SetChannelID(987654321)

	const ssrc = 42
	s.AssignSsrcToCodec(ssrc, godave.CodecOpus)

	s.OnSelectProtocolAck(1)
	if len(cb.lastKeyPackage()) == 0 {
		t.Fatal("expected a key package after protocol ack")
	}
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.OnDavePrepareTransition(0, 1)

	if !s.State().Ready {
		t.Fatal("State().Ready should be true once the sole-member epoch is active")
	}

	// Extra sanity: the bot can encrypt (epoch is genuinely active).
	plaintext := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	out := make([]byte, s.MaxEncryptedFrameSize(len(plaintext)))
	n, err := s.Encrypt(ssrc, plaintext, out)
	if err != nil {
		t.Fatalf("Encrypt while alone failed: %v", err)
	}
	if !frame.LooksLikeDAVEFrame(out[:n]) {
		t.Fatalf("expected an encrypted DAVE frame, got passthrough/plaintext: %x", out[:n])
	}

	// 1. Raw epoch authenticator: 32 bytes (DHKEMP256 AuthenticationSecret).
	secret, err := s.EpochAuthenticator(context.Background())
	if err != nil {
		t.Fatalf("EpochAuthenticator after sole-member: %v", err)
	}
	if want := 32; len(secret) != want {
		t.Fatalf("EpochAuthenticator secret len = %d, want %d", len(secret), want)
	}

	// 2. Displayable code: 30 ASCII digits, no separators, deterministic
	//    within the same epoch (calling it twice returns the same value).
	code1, err := s.EpochAuthenticatorCode(context.Background())
	if err != nil {
		t.Fatalf("EpochAuthenticatorCode: %v", err)
	}
	if len(code1) != 30 {
		t.Fatalf("code len = %d, want 30", len(code1))
	}
	for _, r := range code1 {
		if r < '0' || r > '9' {
			t.Fatalf("non-digit %q in %q", r, code1)
		}
	}
	code2, err := s.EpochAuthenticatorCode(context.Background())
	if err != nil {
		t.Fatalf("EpochAuthenticatorCode (2nd call): %v", err)
	}
	if code1 != code2 {
		t.Fatalf("EpochAuthenticatorCode not deterministic within epoch: %q vs %q", code1, code2)
	}

	// 3. Cross-check the code against an independent reimplementation of
	//    protocol.md's "Displayable Codes" algorithm (30/5), to catch
	//    regressions without coupling to mediakeys.DisplayableCode.
	wantCode := computedDisplayableCode(t, secret)
	if code1 != wantCode {
		t.Fatalf("EpochAuthenticatorCode = %q, want %q from raw secret", code1, wantCode)
	}
}

// computedDisplayableCode is an independent reimplementation of protocol.md's
// "Displayable Codes" algorithm for the epoch authenticator (32 bytes -> 30
// digits in 6 groups of 5). Used by the test to validate that
// mediakeys.DisplayableCode matches the spec without depending on it.
func computedDisplayableCode(t *testing.T, secret []byte) string {
	t.Helper()
	const codeLen, groupSize = 30, 5
	if len(secret) < (codeLen/groupSize)*groupSize {
		t.Fatalf("secret too short for reference: %d bytes", len(secret))
	}
	const digits = "0123456789"
	var b strings.Builder
	b.Grow(codeLen)
	for i := range codeLen / groupSize {
		var n uint64
		for j := range groupSize {
			n = (n << 8) | uint64(secret[i*groupSize+j])
		}
		n %= 100000
		buf := make([]byte, groupSize)
		for k := groupSize - 1; k >= 0; k-- {
			buf[k] = digits[n%10]
			n /= 10
		}
		b.Write(buf)
	}

	return b.String()
}
