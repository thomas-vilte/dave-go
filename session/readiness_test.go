package session

import (
	"testing"

	"github.com/thomas-vilte/dave-go/mediakeys"
)

// TestState_ProtocolVersionExposed covers that the internal protocolVersion
// is reflected in State().ProtocolVersion across the three opcodes that
// update it (SELECT_PROTOCOL_ACK, PREPARE_EPOCH, PREPARE_TRANSITION).
func TestState_ProtocolVersionExposed(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New(nil, "123456789", cb).(*session)

	// Before any opcode: v0, Ready false.
	st := s.State()
	if st.ProtocolVersion != 0 {
		t.Fatalf("ProtocolVersion pre-ack = %d, want 0", st.ProtocolVersion)
	}
	if st.Ready {
		t.Fatal("Ready pre-ack = true, want false")
	}

	// OnSelectProtocolAck(v>0) updates it.
	s.OnSelectProtocolAck(1)
	if got := s.State().ProtocolVersion; got != 1 {
		t.Fatalf("ProtocolVersion after OnSelectProtocolAck = %d, want 1", got)
	}

	// OnDavePrepareEpoch with epoch==1 resets state but must still report >0.
	s.OnDavePrepareEpoch(1, 1)
	if got := s.State().ProtocolVersion; got != 1 {
		t.Fatalf("ProtocolVersion after OnDavePrepareEpoch = %d, want 1", got)
	}

	// OnDavePrepareTransition also updates it.
	s.OnDavePrepareTransition(5, 1)
	if got := s.State().ProtocolVersion; got != 1 {
		t.Fatalf("ProtocolVersion after OnDavePrepareTransition = %d, want 1", got)
	}
}

// TestState_ReadyFalse_DistinguishesV0_FromHandshake verifies that an
// integrator with access to State can tell apart the two cases where
// Ready()==false: stable v0 (ProtocolVersion==0) and a transient handshake
// (ProtocolVersion>0). The recommended pattern is to gate on
// (Ready || ProtocolVersion == 0): passthrough forever on v0, hold during
// the handshake.
func TestState_ReadyFalse_DistinguishesV0_FromHandshake(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New(nil, "123456789", cb).(*session)

	// Stable v0: Ready=false && ProtocolVersion=0 → "no E2EE forever".
	st := s.State()
	if st.Ready || st.ProtocolVersion != 0 {
		t.Fatalf("expected v0: Ready=%v ProtocolVersion=%d", st.Ready, st.ProtocolVersion)
	}
	if !st.Ready && st.ProtocolVersion != 0 {
		t.Fatal("v0 state was not recognized as stable no-E2EE")
	}

	// Transient handshake: OnSelectProtocolAck(1) leaves ProtocolVersion=1,
	// still !Ready.
	s.OnSelectProtocolAck(1)
	st = s.State()
	if st.Ready {
		t.Fatal("Ready should be false during a transient handshake")
	}
	if st.ProtocolVersion == 0 {
		t.Fatal("ProtocolVersion==0 during transient handshake, want >0")
	}
	// Integrator logic: hold frames in this case.
	if st.ProtocolVersion == 0 || st.Ready {
		t.Fatal("transient handshake was not identified")
	}

	// Activate an epoch (sole-member reset) → Ready=true.
	ratchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	s.mu.Lock()
	// Minimal path to reach Ready without driving the full MLS flow: sole-member.
	s.sendRatchet = ratchet
	s.activeEpoch = &epochState{id: 4, groupID: []byte("g")}
	s.mu.Unlock()
	st = s.State()
	if !st.Ready {
		t.Fatal("Ready=false after setting sendRatchet+activeEpoch")
	}
}

// TestReady_PatternGateReadyOrV0 covers that the recommended pattern
// (Ready || ProtocolVersion == 0) composes correctly with the State
// snapshot: a bot on v0 can use the pattern without touching internal code
// paths, and a transient handshake doesn't let it proceed by mistake.
func TestReady_PatternGateReadyOrV0(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New(nil, "123456789", cb).(*session)

	// Stable v0: the "proceed" pattern (passthrough forever).
	st := s.State()
	if st.Ready || st.ProtocolVersion != 0 {
		t.Fatal("expected stable v0 at session start")
	}
	proceed := st.Ready || st.ProtocolVersion == 0
	if !proceed {
		t.Fatal("stable v0 should allow proceed via the recommended pattern")
	}

	// Transient handshake: the "hold" pattern.
	s.OnSelectProtocolAck(1)
	st = s.State()
	proceed = st.Ready || st.ProtocolVersion == 0
	if proceed {
		t.Fatal("transient handshake should hold (got proceed=true)")
	}

	// Ready=true: the "proceed" pattern via Ready.
	ratchet, _ := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	s.mu.Lock()
	s.sendRatchet = ratchet
	s.activeEpoch = &epochState{id: 4, groupID: []byte("g")}
	s.mu.Unlock()
	st = s.State()
	proceed = st.Ready || st.ProtocolVersion == 0
	if !proceed {
		t.Fatal("Ready=true should allow proceed")
	}
}
