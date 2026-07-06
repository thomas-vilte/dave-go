package session

import (
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/mediakeys"
)

func newRatchet(t *testing.T, b byte) *mediakeys.KeyRatchet {
	t.Helper()
	seed := make([]byte, mediakeys.BaseSecretLen)
	for i := range seed {
		seed[i] = b
	}
	r, err := mediakeys.NewKeyRatchet(seed)
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	return r
}

// setupForActivation builds a session whose active epoch is `oldMembers` (with
// the bot as sender) and whose pending epoch is `newMembers`, ready for
// activatePendingEpochLocked. The send counter is advanced so a reset is
// observable.
func setupForActivation(t *testing.T, oldMembers, newMembers []godave.UserID) *session {
	t.Helper()
	s := New(nil, "bot", testCallbacks{}).(*session)
	bot := s.userID

	oldSenders := map[godave.UserID]*senderState{}
	for _, m := range oldMembers {
		oldSenders[m] = &senderState{ratchet: newRatchet(t, 0x01)}
	}
	newSenders := map[godave.UserID]*senderState{}
	for _, m := range newMembers {
		newSenders[m] = &senderState{ratchet: newRatchet(t, 0x02)}
	}

	s.mu.Lock()
	s.activeEpoch = &epochState{id: 0, senders: oldSenders}
	s.sendRatchet = oldSenders[bot].ratchet
	s.pendingEpoch = &epochState{id: 1, groupID: []byte("g"), senders: newSenders}
	s.pendingGroupID = []byte("g")
	s.mu.Unlock()

	// Advance the counter so we can tell whether activation reset it.
	for range 5 {
		s.sendCounter.Next()
	}

	return s
}

// TestActivate_SkipsSendRetentionOnJoin: when the new epoch adds a member (a
// join), the previous send ratchet must NOT be retained — retaining it would
// black out the joiner (who holds no old-epoch keys) for the whole TTL. Instead
// the bot switches atomically and resets the nonce.
func TestActivate_SkipsSendRetentionOnJoin(t *testing.T) {
	s := setupForActivation(t, []godave.UserID{"bot"}, []godave.UserID{"bot", "joiner"})

	s.mu.Lock()
	s.activatePendingEpochLocked()
	retained := s.retainedSendRatchet
	counter := s.sendCounter.Current()
	sendIsNew := s.sendRatchet == s.activeEpoch.senders["bot"].ratchet
	s.mu.Unlock()

	if retained != nil {
		t.Error("send ratchet must NOT be retained when the new epoch adds a member")
	}
	if counter != 0 {
		t.Errorf("send counter must reset to 0 on atomic switch, got %d", counter)
	}
	if !sendIsNew {
		t.Error("send ratchet must switch to the new epoch's ratchet")
	}
}

// TestActivate_RetainsSendRatchetWhenNoJoin: when the new epoch does not add a
// member (same membership, or a removal), retention is preserved — every
// receiver was in the old epoch and can still decrypt the retained frames,
// bridging execute_transition jitter.
func TestActivate_RetainsSendRatchetWhenNoJoin(t *testing.T) {
	t.Run("same members", func(t *testing.T) {
		s := setupForActivation(t, []godave.UserID{"bot", "other"}, []godave.UserID{"bot", "other"})

		s.mu.Lock()
		s.activatePendingEpochLocked()
		retained := s.retainedSendRatchet
		windows := s.stats.TransitionWindows
		s.mu.Unlock()

		if retained == nil {
			t.Error("send ratchet should be retained when membership is unchanged")
		}
		if windows != 1 {
			t.Errorf("TransitionWindows = %d, want 1", windows)
		}
	})

	t.Run("member removed", func(t *testing.T) {
		s := setupForActivation(t, []godave.UserID{"bot", "leaver"}, []godave.UserID{"bot"})

		s.mu.Lock()
		s.activatePendingEpochLocked()
		retained := s.retainedSendRatchet
		s.mu.Unlock()

		if retained == nil {
			t.Error("send ratchet should be retained on a removal (new members ⊆ old)")
		}
	})
}
