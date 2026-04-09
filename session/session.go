package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/codecs"
	"github.com/thomas-vilte/dave-go/frame"
	"github.com/thomas-vilte/dave-go/mediakeys"
)

var _ godave.Session = (*Session)(nil)

type Session struct {
	logger    *slog.Logger
	userID    godave.UserID
	callbacks godave.Callbacks

	mu sync.RWMutex

	channelID       godave.ChannelID
	protocolVersion uint16

	ssrcCodecs map[uint32]codecs.Kind
	users      map[godave.UserID]struct{}

	activeTransitionID  uint16
	pendingTransitionID uint16

	activeEpoch   *epochState
	pendingEpoch  *epochState
	retainedEpoch []*epochState

	sendCounter *mediakeys.NonceCounter
	sendRatchet *mediakeys.KeyRatchet

	mlsClient *mlsClientWrapper

	groupID        []byte
	pendingGroupID []byte

	externalSenderPackage []byte
	pendingKeyPackage     []byte
	lastProposalBatch     []byte

	// proposalQueue holds proposal batches received while a pendingEpoch is
	// waiting for ExecuteTransition. They are replayed in order once the
	// pending epoch is activated, preventing intermediate epoch states from
	// being lost when Discord DS sends multiple proposal batches in quick
	// succession before confirming the previous transition.
	proposalQueue [][]byte

	// pendingCommitBytes is the raw commit we sent to Discord DS (op28).
	// If op29 arrives with a DIFFERENT commit (another client's commit won),
	// we restore preCommitState, clear pendingEpoch, and process the winner.
	pendingCommitBytes  []byte
	preCommitGroupState []byte

	epochReady  chan struct{}
	encryptLogs int
}

type epochState struct {
	id        uint64
	groupID   []byte
	senders   map[godave.UserID]*senderState
	expiresAt time.Time
}

type senderState struct {
	ratchet  *mediakeys.KeyRatchet
	expander *mediakeys.NonceExpander
}

func NewSession(logger *slog.Logger, userID godave.UserID, callbacks godave.Callbacks) godave.Session {
	if logger == nil {
		logger = slog.Default()
	}

	return &Session{
		logger:      logger,
		userID:      userID,
		callbacks:   callbacks,
		ssrcCodecs:  make(map[uint32]codecs.Kind),
		users:       make(map[godave.UserID]struct{}),
		sendCounter: mediakeys.NewNonceCounter(),
		epochReady:  make(chan struct{}),
	}
}

func (s *Session) MaxSupportedProtocolVersion() int {
	return 1
}

func (s *Session) SetChannelID(channelID godave.ChannelID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channelID = channelID
}

func (s *Session) AssignSsrcToCodec(ssrc uint32, codec godave.Codec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ssrcCodecs[ssrc] = toCodecKind(codec)
}

func (s *Session) MaxEncryptedFrameSize(frameSize int) int {
	return frameSize + 64
}

func (s *Session) resetEpochReadyLocked() {
	s.epochReady = make(chan struct{})
}

func (s *Session) signalEpochReadyLocked() {
	select {
	case <-s.epochReady:
		return
	default:
		close(s.epochReady)
	}
}

func (s *Session) waitForActiveEpoch(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	waitLogged := false

	for {
		s.mu.Lock()
		if s.activeEpoch != nil && s.sendRatchet != nil {
			if waitLogged {
				s.logger.Info("active epoch became available")
			}
			s.mu.Unlock()
			return nil
		}
		ready := s.epochReady
		remaining := time.Until(deadline)
		if !waitLogged {
			s.logger.Info("waiting for active epoch", "remaining_ms", remaining.Milliseconds())
			waitLogged = true
		}
		s.mu.Unlock()

		if remaining <= 0 {
			s.logger.Error("timed out waiting for active epoch")
			return ErrNoActiveEpoch
		}

		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		select {
		case <-ready:
			cancel()
		case <-ctx.Done():
			cancel()
			return ErrNoActiveEpoch
		}
	}
}

func (s *Session) Encrypt(ssrc uint32, frameData []byte, encryptedFrame []byte) (int, error) {
	s.mu.RLock()
	_, ok := s.ssrcCodecs[ssrc]
	s.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("no codec assigned for ssrc %d", ssrc)
	}

	if err := s.waitForActiveEpoch(3 * time.Second); err != nil {
		return 0, fmt.Errorf("session: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	kind, ok := s.ssrcCodecs[ssrc]
	if !ok || kind == codecs.CodecUnknown {
		kind = codecs.CodecOpus
	}

	fullNonce, truncatedNonce, generation := s.sendCounter.Next()
	key, err := s.sendRatchet.GetKey(generation)
	if err != nil {
		return 0, err
	}
	keyPreviewLen := 8
	if len(key) < keyPreviewLen {
		keyPreviewLen = len(key)
	}

	encrypted, err := codecs.Encrypt(kind, frameData, key, truncatedNonce)
	if err != nil {
		return 0, err
	}
	framePreviewLen := 24
	if len(encrypted) < framePreviewLen {
		framePreviewLen = len(encrypted)
	}

	s.encryptLogs++
	if s.encryptLogs <= 10 {
		s.logger.Info("frame encrypted",
			"packet_index", s.encryptLogs,
			"ssrc", ssrc,
			"epoch", s.activeEpoch.id,
			"nonce", fullNonce,
			"generation", generation,
			"truncated_nonce", truncatedNonce,
			"media_key_prefix", hex.EncodeToString(key[:keyPreviewLen]),
			"plaintext_size", len(frameData),
			"encrypted_size", len(encrypted),
			"encrypted_prefix", hex.EncodeToString(encrypted[:framePreviewLen]),
		)
	} else {
		s.logger.Debug("frame encrypted", "ssrc", ssrc, "epoch", s.activeEpoch.id, "nonce", fullNonce, "generation", generation, "plaintext_size", len(frameData), "encrypted_size", len(encrypted))
	}

	if cap(encryptedFrame) < len(encrypted) {
		return 0, fmt.Errorf("encrypted frame buffer too small: need %d, have %d", len(encrypted), cap(encryptedFrame))
	}
	n := copy(encryptedFrame[:len(encrypted)], encrypted)
	return n, nil
}

func (s *Session) MaxDecryptedFrameSize(_ godave.UserID, frameSize int) int {
	return frameSize
}

func (s *Session) Decrypt(userID godave.UserID, frameData []byte, decryptedFrame []byte) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parsed, err := frame.Parse(frameData)
	if err != nil {
		return 0, err
	}

	candidates := make([]*epochState, 0, 2+len(s.retainedEpoch))
	if s.activeEpoch != nil {
		candidates = append(candidates, s.activeEpoch)
	}
	if s.pendingEpoch != nil {
		candidates = append(candidates, s.pendingEpoch)
	}
	candidates = append(candidates, s.retainedEpoch...)

	var lastErr error
	for _, epoch := range candidates {
		if epoch == nil {
			continue
		}

		sender, ok := epoch.senders[userID]
		if !ok || sender == nil {
			continue
		}

		fullNonce := sender.expander.Expand(parsed.TruncatedNonce)
		generation := uint32(fullNonce >> 24)

		key, err := sender.ratchet.GetKey(generation)
		if err != nil {
			lastErr = err
			continue
		}

		plaintext, _, err := frame.Decrypt(frame.DecryptParams{
			Ciphertext: frameData,
			Key:        key,
		})
		if err != nil {
			lastErr = err
			continue
		}

		n := copy(decryptedFrame, plaintext)
		return n, nil
	}

	if lastErr != nil {
		return 0, lastErr
	}
	return 0, ErrDecryptionFailed
}

func (s *Session) AddUser(userID godave.UserID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[userID] = struct{}{}
}

func (s *Session) RemoveUser(userID godave.UserID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, userID)
}

func (s *Session) OnSelectProtocolAck(protocolVersion uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protocolVersion = protocolVersion
	if protocolVersion > 0 {
		if err := s.ensurePendingKeyPackageLocked(); err != nil {
			s.logger.Error("failed to prepare key package on protocol ack", "error", err)
		}
	}
}

func (s *Session) OnDavePrepareTransition(transitionID uint16, protocolVersion uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingTransitionID = transitionID
	s.protocolVersion = protocolVersion
}

func (s *Session) OnDaveExecuteTransition(transitionID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("[DAVE] OnDaveExecuteTransition", "transition_id", transitionID, "pending_epoch_set", s.pendingEpoch != nil)
	s.activeTransitionID = transitionID
	s.activatePendingEpochLocked()
	s.pendingTransitionID = 0
}

func (s *Session) OnDavePrepareEpoch(epoch int, protocolVersion uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.protocolVersion = protocolVersion
	if epoch != 1 {
		return
	}

	s.activeEpoch = nil
	s.pendingEpoch = nil
	s.retainedEpoch = nil
	s.groupID = nil
	s.pendingGroupID = nil
	s.pendingCommitBytes = nil
	s.preCommitGroupState = nil
	s.proposalQueue = nil
	s.resetEpochReadyLocked()
	s.sendCounter.Reset()
	s.sendRatchet = nil
	s.pendingKeyPackage = nil
	s.mlsClient = nil

	if err := s.ensurePendingKeyPackageLocked(); err != nil {
		s.logger.Error("failed to prepare key package", "error", err)
	}
}

func (s *Session) OnDaveMLSExternalSenderPackage(externalSenderPackage []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.externalSenderPackage = append([]byte(nil), externalSenderPackage...)
	if err := s.createGroupWithExternalSenderLocked(); err != nil {
		s.logger.Error("failed to create mls group with external sender", "error", err)
	}
}

func (s *Session) OnDaveMLSProposals(proposals []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastProposalBatch = append([]byte(nil), proposals...)
	s.logger.Info("[DAVE] OnDaveMLSProposals", "size", len(proposals), "group_id", fmt.Sprintf("%x", s.groupID), "has_group", len(s.groupID) > 0)

	// If a pendingEpoch is already waiting for ExecuteTransition, queue this
	// batch instead of committing immediately. Committing again would advance
	// the local group state past what Discord DS has accepted, causing the
	// intermediate epoch to be overwritten and audio keys to diverge.
	if s.pendingEpoch != nil {
		s.logger.Info("[DAVE] OnDaveMLSProposals: pendingEpoch in flight, queuing proposals", "queue_len", len(s.proposalQueue)+1)
		s.proposalQueue = append(s.proposalQueue, append([]byte(nil), proposals...))
		return
	}

	s.processAndCommitProposalBatchLocked(proposals)
}

// processAndCommitProposalBatchLocked processes a proposal batch and commits.
// Must be called with s.mu held.
func (s *Session) processAndCommitProposalBatchLocked(proposals []byte) {
	if err := s.ensureMLSClientLocked(); err != nil {
		s.logger.Error("failed to init mls client", "error", err)
		return
	}
	if err := s.processProposalBatchLocked(proposals); err != nil {
		s.logger.Error("failed to process proposals", "error", err, "size", len(proposals))
		return
	}
	if len(s.groupID) == 0 {
		s.logger.Warn("[DAVE] OnDaveMLSProposals: no group after processing proposals, skipping commit")
		return
	}
	if err := s.commitProposalsLocked(); err != nil {
		s.logger.Error("failed to commit proposals", "error", err)
		return
	}
	s.logger.Info("mls proposals processed and committed", "size", len(proposals), "pending_epoch_set", s.pendingEpoch != nil, "pending_epoch_id", func() uint64 {
		if s.pendingEpoch != nil {
			return s.pendingEpoch.id
		}
		return 0
	}())
}

func (s *Session) OnDaveMLSPrepareCommitTransition(transitionID uint16, commitMessage []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("[DAVE] OnDaveMLSPrepareCommitTransition", "transition_id", transitionID, "commit_size", len(commitMessage), "pending_epoch_set", s.pendingEpoch != nil, "commit_hex_prefix", fmt.Sprintf("%x", commitMessage[:minInt(32, len(commitMessage))]))
	s.pendingTransitionID = transitionID
	if err := s.ensureMLSClientLocked(); err != nil {
		s.logger.Error("failed to init mls client", "error", err)
		return
	}

	// If pendingEpoch is set AND the DS is echoing our exact commit back, we
	// were the committer and our local epoch is correct — skip re-processing.
	//
	// If the DS echoes a DIFFERENT commit (another client's commit won the
	// race), we must roll back our local state to the pre-commit snapshot and
	// process the winning commit instead. Without this, the bot's epoch diverges
	// from Discord's and audio decryption fails.
	if s.pendingEpoch != nil && bytes.Equal(s.pendingCommitBytes, commitMessage) {
		s.logger.Debug("skipping commit re-processing: we were the committer", "transition_id", transitionID)
		s.pendingCommitBytes = nil
		s.preCommitGroupState = nil
	} else {
		if s.pendingEpoch != nil {
			// Our commit lost; restore pre-commit state before processing the winner.
			s.logger.Info("[DAVE] OnDaveMLSPrepareCommitTransition: competing commit won, rolling back",
				"transition_id", transitionID,
				"our_commit_size", len(s.pendingCommitBytes),
				"winning_commit_size", len(commitMessage))
			if err := s.restorePreCommitStateLocked(); err != nil {
				s.logger.Error("failed to restore pre-commit state", "transition_id", transitionID, "error", err)
				if s.callbacks != nil {
					_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
				}
				return
			}
		}
		if err := s.processCommitLocked(commitMessage); err != nil {
			s.logger.Error("failed to process commit", "transition_id", transitionID, "error", err)
			if s.callbacks != nil {
				_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
			}
			return
		}
	}

	if s.callbacks != nil {
		if err := s.callbacks.SendReadyForTransition(transitionID); err != nil {
			s.logger.Error("failed to send ready for transition", "transition_id", transitionID, "error", err)
		}
	}

	if transitionID == 0 {
		s.logger.Info("[DAVE] activating epoch immediately for initial transition (transitionID=0)")
		s.activeTransitionID = 0
		s.activatePendingEpochLocked()
		s.pendingTransitionID = 0
	}
}

func (s *Session) OnDaveMLSWelcome(transitionID uint16, welcomeMessage []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("[DAVE] OnDaveMLSWelcome", "transition_id", transitionID, "welcome_size", len(welcomeMessage))
	s.pendingTransitionID = transitionID

	// If we have a pending epoch it means we previously committed. A Welcome
	// arriving means Discord DS chose another member's commit over ours — our
	// commit was rejected. Roll back our local state to the pre-commit snapshot
	// so that joinPendingWelcomeLocked operates from the correct epoch.
	if s.pendingEpoch != nil {
		s.logger.Info("[DAVE] OnDaveMLSWelcome: our commit was rejected by DS (Welcome received), rolling back",
			"transition_id", transitionID)
		if err := s.restorePreCommitStateLocked(); err != nil {
			s.logger.Error("failed to restore pre-commit state on Welcome", "transition_id", transitionID, "error", err)
			if s.callbacks != nil {
				_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
			}
			return
		}
		// Also clear the proposal queue — those proposals were committed against
		// our (now-discarded) epoch; the DS will send fresh proposals if needed.
		s.proposalQueue = nil
	}

	if err := s.ensureMLSClientLocked(); err != nil {
		s.logger.Error("failed to init mls client", "error", err)
		return
	}

	if err := s.joinPendingWelcomeLocked(welcomeMessage); err != nil {
		s.logger.Error("failed to join welcome", "transition_id", transitionID, "error", err)
		if s.callbacks != nil {
			_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
		}
		return
	}
	s.logger.Info("[DAVE] OnDaveMLSWelcome: joined successfully", "pending_epoch_set", s.pendingEpoch != nil, "pending_epoch_id", func() uint64 {
		if s.pendingEpoch != nil {
			return s.pendingEpoch.id
		}
		return 0
	}())

	if s.callbacks != nil {
		if err := s.callbacks.SendReadyForTransition(transitionID); err != nil {
			s.logger.Error("failed to send ready for transition", "transition_id", transitionID, "error", err)
		}
	}

	if transitionID == 0 {
		s.logger.Info("[DAVE] activating epoch immediately from welcome (transitionID=0)")
		s.activeTransitionID = 0
		s.activatePendingEpochLocked()
		s.pendingTransitionID = 0
	}
}

func toCodecKind(codec godave.Codec) codecs.Kind {
	switch codec {
	case godave.CodecOpus:
		return codecs.CodecOpus
	default:
		return codecs.CodecUnknown
	}
}
