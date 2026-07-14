package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
	"github.com/thomas-vilte/mls-go/credentials"
)

// writeVLBytes encodes b as an MLS variable-length vector (the RFC 9000 varint
// length prefix used by mlspp), matching readTLSVectorLength on the read side.
func writeVLBytes(b []byte) []byte {
	n := len(b)
	var hdr []byte
	switch {
	case n < 0x40:
		hdr = []byte{byte(n)}
	case n < 0x4000:
		hdr = []byte{byte(0x40 | (n >> 8)), byte(n)}
	default:
		hdr = []byte{byte(0x80 | (n >> 24)), byte(n >> 16), byte(n >> 8), byte(n)}
	}

	return append(hdr, b...)
}

// buildExternalSenderPackage builds an opcode-25 external sender payload the way
// the voice gateway sends it: VL(signature_public_key) || Credential_inline.
func buildExternalSenderPackage(t *testing.T) []byte {
	t.Helper()
	pkg, _ := buildExternalSenderPackageWithKey(t)

	return pkg
}

// buildExternalSenderPackageWithKey is like buildExternalSenderPackage but also
// returns the ECDH private key so tests can sign proposals as the external
// sender (simulating the gateway, which is how DAVE delivers proposals in
// reality — not as a group member).
func buildExternalSenderPackageWithKey(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate external sender key: %v", err)
	}
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("convert external sender key to ECDH: %v", err)
	}

	cred := credentials.NewBasicCredentialFromUint64(1)

	return append(writeVLBytes(ecdhPub.Bytes()), cred.Marshal()...), priv
}

// TestSoleMemberReset_EncryptsWhileAlone reproduces the DAVE "Sole member reset":
// the bot ends up as the only member, so the gateway sends the external sender
// package and prepare_transition with transition_id 0, but never a commit or
// welcome. The bot must still build its own sole-member epoch, derive a send
// ratchet, and end up able to encrypt its own audio while alone.
func TestSoleMemberReset_EncryptsWhileAlone(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)
	s.SetChannelID(987654321)

	const ssrc = 42
	s.AssignSsrcToCodec(ssrc, godave.CodecOpus)

	// E2EE upgrade: Discord sends select_protocol_ack with a non-zero version.
	s.OnSelectProtocolAck(1)
	if len(cb.lastKeyPackage()) == 0 {
		t.Fatal("expected a key package after protocol ack")
	}

	// Gateway delivers the external sender, then prepare_transition 0 with no
	// commit/welcome (the sole-member case).
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.OnDavePrepareTransition(0, 1)

	s.mu.RLock()
	if s.activeEpoch == nil || s.sendRatchet == nil {
		s.mu.RUnlock()
		t.Fatal("sole member has no active epoch / send ratchet, cannot encrypt alone")
	}
	s.mu.RUnlock()

	if !s.State().Ready {
		t.Fatal("State().Ready should be true once the sole-member epoch is active")
	}

	// The bot can now actually encrypt: the output is a real DAVE frame, not a
	// passthrough copy of the plaintext.
	plaintext := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	out := make([]byte, s.MaxEncryptedFrameSize(len(plaintext)))
	n, err := s.Encrypt(ssrc, plaintext, out)
	if err != nil {
		t.Fatalf("Encrypt while alone failed: %v", err)
	}
	if !frame.LooksLikeDAVEFrame(out[:n]) {
		t.Fatalf("expected an encrypted DAVE frame, got passthrough/plaintext: %x", out[:n])
	}
	if got := s.Stats().PassthroughFrames; got != 0 {
		t.Fatalf("expected 0 passthrough frames once E2EE is active, got %d", got)
	}
}

// TestSoleMemberReset_NoExternalSenderStaysPassthrough verifies that a
// transition_id 0 with no external sender context (a protocol-version-0 session)
// leaves the session in passthrough instead of erroring.
func TestSoleMemberReset_NoExternalSenderStaysPassthrough(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

	s.OnDavePrepareTransition(0, 0)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeEpoch != nil || s.sendRatchet != nil {
		t.Fatal("expected no epoch when there is no external sender (passthrough)")
	}
}
