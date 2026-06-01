package session

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"

	"github.com/thomas-vilte/dave-go/mediakeys"
)

const epochRetention = 10 * time.Second

type mlsClientWrapper struct {
	client *mls.Client
	store  *memorystore.Store
}

type exporterAdapter struct {
	store   *memorystore.Store
	groupID []byte
}

func (e exporterAdapter) Export(label string, ctx []byte, length int) ([]byte, error) {
	if e.store == nil {
		return nil, fmt.Errorf("mls exporter store is nil")
	}

	state, err := e.store.LoadGroupState(context.Background(), group.NewGroupID(e.groupID))
	if err != nil {
		return nil, fmt.Errorf("load group state for exporter: %w", err)
	}

	g, err := group.UnmarshalGroupState(state)
	if err != nil {
		return nil, fmt.Errorf("unmarshal group state for exporter: %w", err)
	}

	if g.EpochSecrets() == nil || g.EpochSecrets().ExporterSecret == nil {
		return nil, fmt.Errorf("exporter secret not available")
	}

	exporterSecretPrefixLen := 8
	exporterSecretBytes := g.EpochSecrets().ExporterSecret.AsSlice()
	if len(exporterSecretBytes) < exporterSecretPrefixLen {
		exporterSecretPrefixLen = len(exporterSecretBytes)
	}

	discordExport, err := mediakeys.ExportWithMLSExporterSecret(g.EpochSecrets().ExporterSecret, g.CipherSuite(), label, ctx, length)
	if err != nil {
		return nil, err
	}

	exportPrefixLen := 8
	if len(discordExport) < exportPrefixLen {
		exportPrefixLen = len(discordExport)
	}

	slog.Default().Debug("[DAVE] exporter derivation",
		"group_id", fmt.Sprintf("%x", e.groupID),
		"label", label,
		"context_prefix", hex.EncodeToString(ctx[:minInt(len(ctx), 8)]),
		"exporter_secret_prefix", hex.EncodeToString(exporterSecretBytes[:exporterSecretPrefixLen]),
		"export_prefix", hex.EncodeToString(discordExport[:exportPrefixLen]),
	)

	return discordExport, nil
}

func userIDToIdentityBytes(userID godave.UserID) ([]byte, uint64, error) {
	n, err := strconv.ParseUint(string(userID), 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("parse user id %q: %w", userID, err)
	}

	// DAVE credential identity = user snowflake as big-endian uint64.
	// Verified against golibdave/libdave wire bytes: identity is BE.
	identity := make([]byte, 8)
	binary.BigEndian.PutUint64(identity, n)
	return identity, n, nil
}

func identityBytesToUserID(identity []byte) (godave.UserID, uint64, error) {
	if len(identity) != 8 {
		return "", 0, fmt.Errorf("unexpected credential identity length: %d", len(identity))
	}

	// DAVE credential identity = user snowflake as big-endian uint64.
	n := binary.BigEndian.Uint64(identity)
	return godave.UserID(strconv.FormatUint(n, 10)), n, nil
}

func (s *session) ensureMLSClientLocked() error {
	if s.mlsClient != nil {
		return nil
	}

	identity, _, err := userIDToIdentityBytes(s.userID)
	if err != nil {
		return err
	}

	store := memorystore.NewStore()
	client, err := mls.NewClient(
		identity,
		ciphersuite.MLS128DHKEMP256,
		mls.WithStorage(store, store),
		mls.WithCacheStrategy(mls.CacheNone),
	)
	if err != nil {
		return fmt.Errorf("create mls client: %w", err)
	}

	s.mlsClient = &mlsClientWrapper{client: client, store: store}
	return nil
}

func (s *session) ensurePendingKeyPackageLocked() error {
	if err := s.ensureMLSClientLocked(); err != nil {
		return err
	}
	if len(s.pendingKeyPackage) > 0 {
		return nil
	}

	// DAVE spec (https://daveprotocol.com/#validation) requires lifetime [0, 2^64-1].
	kp, err := s.mlsClient.client.FreshKeyPackageBytes(
		context.Background(),
		keypackages.InfiniteLifetime(),
	)
	if err != nil {
		return fmt.Errorf("generate fresh key package: %w", err)
	}

	s.pendingKeyPackage = append([]byte(nil), kp...)
	if s.callbacks != nil {
		// libdave sends the marshalled KeyPackage directly for opcode 26.
		if err := s.callbacks.SendMLSKeyPackage(kp); err != nil {
			return fmt.Errorf("send mls key package: %w", err)
		}
	}
	return nil
}

func (s *session) joinPendingWelcomeLocked(welcome []byte) error {
	groupID, err := s.mlsClient.client.JoinGroup(context.Background(), welcome)
	if err != nil {
		return fmt.Errorf("join group from welcome: %w", err)
	}

	// Update groupID immediately so that processCommitLocked and
	// processProposalBatchLocked target the Welcome-joined group, not any
	// stale locally-created group that was never confirmed by the DS.
	s.groupID = append([]byte(nil), groupID...)
	s.pendingGroupID = append([]byte(nil), groupID...)
	epochState, err := s.rebuildEpochStateLocked(groupID)
	if err != nil {
		return err
	}
	s.pendingEpoch = epochState
	return nil
}

func (s *session) processCommitLocked(commit []byte) error {
	if len(s.groupID) == 0 {
		return fmt.Errorf("no active group for commit")
	}

	if err := s.mlsClient.client.ProcessCommit(context.Background(), s.groupID, commit); err != nil {
		return fmt.Errorf("process commit: %w", err)
	}

	epochState, err := s.rebuildEpochStateLocked(s.groupID)
	if err != nil {
		return err
	}

	s.pendingEpoch = epochState
	s.pendingGroupID = append([]byte(nil), s.groupID...)
	return nil
}

// readTLSVectorLength decodes an MLS variable-length integer (RFC 9000 §16 encoding
// used by mlspp for TLS vector length prefixes).
//
// The top two bits of the first byte encode the width:
//
//	00xxxxxx                         → 1 byte,  6-bit value  (0–63)
//	01xxxxxx xxxxxxxx                → 2 bytes, 14-bit value (64–16 383)
//	10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx → 4 bytes, 30-bit value (16 384–1 073 741 823)
//
// Returns (length, bytesConsumed, error).
func readTLSVectorLength(data []byte) (uint32, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty vector length")
	}

	prefix := data[0] >> 6
	switch prefix {
	case 0: // 1-byte encoding
		return uint32(data[0] & 0x3F), 1, nil
	case 1: // 2-byte encoding
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("truncated 2-byte vector length")
		}
		v := uint32(data[0]&0x3F)<<8 | uint32(data[1])
		return v, 2, nil
	case 2: // 4-byte encoding
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("truncated 4-byte vector length")
		}
		v := uint32(data[0]&0x3F)<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		return v, 4, nil
	default:
		return 0, 0, fmt.Errorf("unsupported 8-byte vector length encoding")
	}
}

func (s *session) processProposalBatchLocked(proposals []byte) error {
	if len(proposals) == 0 {
		s.logger.Debug("[DAVE] processProposalBatchLocked: empty proposals")
		return nil
	}
	if len(s.groupID) == 0 {
		// DAVE spec §5: if no local group exists, proposals are ignored.
		s.logger.Debug("[DAVE] processProposalBatchLocked: no group, ignoring proposals")
		return nil
	}

	// DAVE_MLSProposals payload format (after opcode consumed by gateway):
	// uint8 operation_type || TLSVector<MLSMessage>
	// operation_type: 0=append, 1=revoke
	if len(proposals) < 1 {
		return fmt.Errorf("proposals too short: %d bytes", len(proposals))
	}

	operationType := proposals[0]
	s.logger.Debug("[DAVE] processProposalBatchLocked", "operation_type", operationType, "total_size", len(proposals))
	if operationType != 0 {
		// revoke: not yet handled — ignore safely
		s.logger.Debug("[DAVE] processProposalBatchLocked: revoke operation, ignoring")
		return nil
	}

	// Parse TLS vector length to get to the raw MLSMessages.
	// Format: operation_type || TLSVector<MLSMessage>
	payload := proposals[1:]
	vecLen, headerSize, err := readTLSVectorLength(payload)
	if err != nil {
		return fmt.Errorf("reading proposals vector length: %w", err)
	}
	end := headerSize + int(vecLen)
	if end > len(payload) {
		return fmt.Errorf("proposals vector truncated: need %d bytes, have %d", end, len(payload))
	}

	s.logger.Debug("[DAVE] proposals vector parsed",
		"vec_len", vecLen,
		"header_size", headerSize,
		"payload_first_32", fmt.Sprintf("%x", payload[:minInt(32, len(payload))]),
		"vector_first_32", fmt.Sprintf("%x", payload[headerSize:minInt(headerSize+32, end)]))

	remaining := payload[headerSize:end]
	for i := 0; len(remaining) > 0; i++ {
		if len(remaining) < 4 {
			return fmt.Errorf("proposal too short: %d bytes", len(remaining))
		}
		wireOriginal := remaining
		s.logger.Debug("[DAVE] parsing proposal", "index", i, "remaining_bytes", len(remaining), "wire_hex", fmt.Sprintf("%x", remaining[:minInt(64, len(remaining))]))

		msg, err := framing.UnmarshalMLSMessage(remaining)
		if err != nil {
			return fmt.Errorf("parse proposal message: %w", err)
		}

		wire := msg.Marshal()
		if len(wire) == 0 {
			return fmt.Errorf("empty marshalled proposal")
		}

		// Use original bytes (not re-marshalled) so ProposalRef hash matches gateway's computation.
		if err := s.mlsClient.client.ProcessPublicMessage(context.Background(), s.groupID, wireOriginal[:len(wire)]); err != nil {
			return fmt.Errorf("process proposal public message: %w", err)
		}
		remaining = remaining[len(wire):]
	}

	s.logger.Debug("[DAVE] processProposalBatchLocked: all proposals processed successfully")
	return nil
}

func (s *session) rebuildEpochStateLocked(groupID []byte) (*epochState, error) {
	members, err := s.mlsClient.client.ListMembers(context.Background(), groupID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}

	epochID, err := s.mlsClient.client.Epoch(context.Background(), groupID)
	if err != nil {
		return nil, fmt.Errorf("read epoch: %w", err)
	}

	state := &epochState{
		id:      epochID,
		groupID: append([]byte(nil), groupID...),
		senders: make(map[godave.UserID]*senderState, len(members)),
	}

	exporter := exporterAdapter{store: s.mlsClient.store, groupID: groupID}
	for _, member := range members {
		memberUserID, senderID, err := identityBytesToUserID(member.Identity)
		if err != nil {
			return nil, fmt.Errorf("decode member identity: %w", err)
		}

		baseSecret, err := mediakeys.DeriveSenderBaseSecret(exporter, senderID)
		if err != nil {
			return nil, fmt.Errorf("derive sender base secret for %s: %w", memberUserID, err)
		}
		baseSecretPreviewLen := 8
		if len(baseSecret) < baseSecretPreviewLen {
			baseSecretPreviewLen = len(baseSecret)
		}

		ratchet, err := mediakeys.NewKeyRatchet(baseSecret)
		if err != nil {
			return nil, fmt.Errorf("build ratchet for %s: %w", memberUserID, err)
		}

		generationZeroKey, err := ratchet.GetKey(0)
		if err != nil {
			return nil, fmt.Errorf("derive generation 0 key for %s: %w", memberUserID, err)
		}
		generationZeroPreviewLen := 8
		if len(generationZeroKey) < generationZeroPreviewLen {
			generationZeroPreviewLen = len(generationZeroKey)
		}

		s.logger.Debug("[DAVE] sender key material derived",
			"epoch_id", epochID,
			"member_user_id", memberUserID,
			"sender_id", senderID,
			"base_secret_prefix", hex.EncodeToString(baseSecret[:baseSecretPreviewLen]),
			"generation0_key_prefix", hex.EncodeToString(generationZeroKey[:generationZeroPreviewLen]),
		)

		state.senders[memberUserID] = &senderState{
			ratchet:  ratchet,
			expander: mediakeys.NewNonceExpander(),
		}
	}

	return state, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *session) activatePendingEpochLocked() {
	s.logger.Debug("[DAVE] activatePendingEpochLocked called", "pending_epoch_set", s.pendingEpoch != nil, "active_epoch_set", s.activeEpoch != nil, "user_id", s.userID)
	if s.pendingEpoch == nil {
		s.logger.Warn("[DAVE] activatePendingEpochLocked: pendingEpoch is nil, no-op")
		return
	}

	if s.activeEpoch != nil {
		s.activeEpoch.expiresAt = time.Now().Add(epochRetention)
		s.retainedEpoch = append(s.retainedEpoch, s.activeEpoch)
		s.logger.Debug("[DAVE] activatePendingEpochLocked: retained previous active epoch", "old_epoch_id", s.activeEpoch.id)
	}

	s.activeEpoch = s.pendingEpoch
	s.pendingEpoch = nil
	s.groupID = append([]byte(nil), s.pendingGroupID...)
	s.pendingGroupID = nil
	s.sendCounter.Reset()

	if sender := s.activeEpoch.senders[s.userID]; sender != nil {
		s.sendRatchet = sender.ratchet
		s.signalEpochReadyLocked()
		s.logger.Debug("[DAVE] activatePendingEpochLocked: epoch activated", "epoch_id", s.activeEpoch.id, "sender_count", len(s.activeEpoch.senders), "send_ratchet_set", true)
	} else {
		s.sendRatchet = nil
		s.logger.Warn("[DAVE] activatePendingEpochLocked: epoch activated but NO send ratchet (self not in senders map)", "epoch_id", s.activeEpoch.id, "sender_count", len(s.activeEpoch.senders))
	}

	s.pruneRetainedEpochsLocked()

	// Drain queued proposal batches now that the pending epoch has been
	// activated. Process them one at a time so that each commit can be
	// queued again if another pending epoch accumulates mid-drain.
	s.drainProposalQueueLocked()
}

func (s *session) drainProposalQueueLocked() {
	for len(s.proposalQueue) > 0 && s.pendingEpoch == nil {
		next := s.proposalQueue[0]
		s.proposalQueue = s.proposalQueue[1:]
		s.logger.Debug("[DAVE] draining queued proposal batch", "size", len(next), "remaining_queue", len(s.proposalQueue))
		s.processAndCommitProposalBatchLocked(next)
	}
}

func (s *session) pruneRetainedEpochsLocked() {
	now := time.Now()
	dst := s.retainedEpoch[:0]
	for _, epoch := range s.retainedEpoch {
		if epoch == nil {
			continue
		}
		if epoch.expiresAt.After(now) {
			dst = append(dst, epoch)
		}
	}
	s.retainedEpoch = dst
}

func (s *session) createGroupWithExternalSenderLocked() error {
	if len(s.groupID) > 0 {
		return nil // group already created
	}
	if len(s.externalSenderPackage) == 0 {
		return fmt.Errorf("no external sender package available")
	}
	if err := s.ensureMLSClientLocked(); err != nil {
		return err
	}

	// DAVE: the MLS group_id must be the channel ID encoded as 8-byte big-endian uint64.
	channelIDBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(channelIDBytes, uint64(s.channelID))

	// Use the same key package that was uploaded to the gateway (op26).
	// The commit is signed by this leaf's private key; the gateway verifies it
	// against the KP it received via op26. Using a different KP here would make
	// the commit signature unverifiable and the gateway would silently reject it.
	groupID, err := s.mlsClient.client.CreateGroupWithExternalSender(
		context.Background(),
		channelIDBytes,
		s.pendingKeyPackage,
		s.externalSenderPackage,
	)
	if err != nil {
		return fmt.Errorf("create mls group: %w", err)
	}

	s.groupID = append([]byte(nil), groupID...)
	s.logger.Info("mls group created", "group_id", fmt.Sprintf("%x", s.groupID))
	return nil
}

// restorePreCommitStateLocked rolls the MLS group back to the snapshot taken
// just before the last commit. Called when Discord DS echoes a different commit
// (i.e. another member's commit won) so that processCommitLocked can apply the
// winning commit from the correct base epoch. Must be called with s.mu held.
func (s *session) restorePreCommitStateLocked() error {
	if len(s.preCommitGroupState) == 0 {
		return fmt.Errorf("no pre-commit state to restore")
	}
	gid := group.NewGroupID(s.groupID)
	if err := s.mlsClient.store.SaveGroupState(context.Background(), gid, s.preCommitGroupState); err != nil {
		return fmt.Errorf("restore pre-commit state: %w", err)
	}
	s.pendingEpoch = nil
	s.pendingGroupID = nil
	s.pendingCommitBytes = nil
	s.preCommitGroupState = nil
	return nil
}

// invalidateAndResendKeyPackageLocked resets the local MLS state and sends a
// new key package to the voice gateway. Called after SendInvalidCommitWelcome
// per the DAVE protocol spec §"Recovery from Invalid Commit or Welcome":
// the client must locally reset MLS state and generate a new key package so
// the voice gateway can re-add the member via a fresh add proposal.
// Must be called with s.mu held.
func (s *session) invalidateAndResendKeyPackageLocked() {
	s.mlsClient = nil
	s.groupID = nil
	s.pendingGroupID = nil
	s.pendingEpoch = nil
	s.pendingCommitBytes = nil
	s.preCommitGroupState = nil
	s.proposalQueue = nil
	s.pendingKeyPackage = nil
	if err := s.ensurePendingKeyPackageLocked(); err != nil {
		s.logger.Error("failed to send new key package after invalid commit/welcome", "error", err)
	}
}

func (s *session) commitProposalsLocked() error {
	s.logger.Debug("[DAVE] commitProposalsLocked: starting commit", "group_id", fmt.Sprintf("%x", s.groupID))

	// Snapshot the pre-commit group state. If Discord DS accepts a competing
	// commit instead of ours, we restore this snapshot so processCommitLocked
	// can apply the DS-winning commit from the correct epoch.
	gid := group.NewGroupID(s.groupID)
	preState, err := s.mlsClient.store.LoadGroupState(context.Background(), gid)
	if err != nil {
		return fmt.Errorf("snapshot pre-commit state: %w", err)
	}

	// DAVE-specific GroupInfo options:
	// - external_pub is NOT needed (DAVE doesn't use external commits)
	// - ratchet_tree IS needed (joiners need the tree to instantiate the group)
	commit, welcome, err := s.mlsClient.client.CommitPendingProposalsWithOptions(
		context.Background(),
		s.groupID,
		mls.CommitPendingProposalsOptions{
			GroupInfoOptions: []group.GroupInfoOption{
				group.WithExternalPub(false),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("commit pending proposals: %w", err)
	}

	s.logger.Debug("[DAVE] commitProposalsLocked: commit created", "commit_size", len(commit), "welcome_size", len(welcome))
	s.logger.Debug("[DAVE] commitProposalsLocked: commit hex", "commit_hex", fmt.Sprintf("%x", commit))

	// CommitPendingProposals advances the local epoch immediately (MergeCommit).
	// Pre-populate pendingEpoch so that when op 29 arrives (gateway echoes the commit
	// back to the committer), OnDaveMLSPrepareCommitTransition can confirm our epoch.
	// If op 29 carries a DIFFERENT commit, restorePreCommitStateLocked() rolls back.
	s.pendingCommitBytes = append([]byte(nil), commit...)
	s.preCommitGroupState = preState

	epochState, err := s.rebuildEpochStateLocked(s.groupID)
	if err != nil {
		return fmt.Errorf("rebuild epoch after commit: %w", err)
	}
	s.pendingEpoch = epochState
	s.pendingGroupID = append([]byte(nil), s.groupID...)

	s.logger.Debug("[DAVE] commitProposalsLocked: pendingEpoch set", "epoch_id", epochState.id, "sender_count", len(epochState.senders), "has_self", func() bool { _, ok := epochState.senders[s.userID]; return ok }())

	// DAVE opcode 28 spec v1.1.2:
	// MLSMessage(commit) || Welcome(struct)
	// CommitPendingProposals returns the welcome already wrapped in an MLSMessage.
	// We MUST unwrap it so the Discord gateway can parse it properly.
	payload := commit
	if len(welcome) > 0 {
		wMsg, err := framing.UnmarshalMLSMessage(welcome)
		if err != nil {
			return fmt.Errorf("unwrap welcome message: %w", err)
		}
		if wMsg.Welcome != nil {
			payload = append(payload, wMsg.Welcome...)
		} else {
			return fmt.Errorf("expected Welcome in MLSMessage")
		}
	}

	if s.callbacks == nil {
		s.logger.Debug("[DAVE] commitProposalsLocked: no callbacks, skipping send")
		return nil
	}
	s.logger.Debug("[DAVE] commitProposalsLocked: sending commit/welcome to gateway", "payload_size", len(payload))
	if err := s.callbacks.SendMLSCommitWelcome(payload); err != nil {
		return err
	}

	// Start a background recovery goroutine. If Discord does not confirm our
	// commit via op:29 within the timeout, the epoch will never activate.
	// The goroutine either exits early when epochReady is closed (normal path)
	// or triggers InvalidCommitWelcome + MLS state reset so Discord re-adds us.
	ready := s.epochReady
	transitionID := s.pendingTransitionID
	go func() {
		select {
		case <-ready:
			// Epoch activated normally — nothing to do.
			return
		case <-time.After(3 * time.Second):
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pendingEpoch == nil {
			return
		}
		s.logger.Warn("[DAVE] commit not confirmed by Discord, triggering recovery", "transition_id", transitionID)
		if s.callbacks != nil {
			_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
		}
		s.invalidateAndResendKeyPackageLocked()
	}()
	return nil
}
