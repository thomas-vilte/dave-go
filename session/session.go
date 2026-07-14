package session

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
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

// Session is a DAVE E2EE session for a single voice connection. It implements
// godave.Session (the encrypt/decrypt/protocol-event contract consumed by the
// voice layer) and additionally exposes observability (State, Stats, WaitReady,
// EpochAuthenticatorCode) and lifecycle (Close, WaitShutdown) methods directly
// on the concrete type — no type assertions needed.
//
// Create one with New, or hand CreateFunc to the voice layer and capture the
// *Session via WithSessionHook. A Session is single-use per voice connection;
// call Close when discarding it (channel move, disconnect).
type Session struct {
	// logger carries the session's correlation fields (dave_session, user_id and,
	// once known, channel_id) so every line can be traced back to one connection.
	// baseLogger keeps the original caller logger to re-bind those fields when the
	// channel becomes known, without dropping anything the integrator bound on top.
	logger     *slog.Logger
	baseLogger *slog.Logger
	id         string

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

	// retainedSendRatchet holds the previous sendRatchet across an epoch
	// transition so the sender keeps producing frames the receiver can still
	// decrypt for up to sendRetentionTTL after the new epoch activates.
	//
	// NOTE: this is a deliberate extension beyond the literal protocol text,
	// not a spec requirement. protocol.md only mandates retention on the
	// RECEIVE side ("Media receivers temporarily retain the sender key
	// ratchets for previous epochs... up to ten seconds") and is explicit
	// that the SEND side switches atomically: "Upon receipt of [execute_
	// transition], media senders begin using the new... key ratchet" and
	// "media senders will continue to use key ratchets from the previous
	// epoch UNTIL the transition is executed" (i.e. not after). By spec
	// design every member should already have the new receive ratchet
	// derived (right after processing the commit, before ready_for_
	// transition is even sent) before any sender could use it, so this
	// padding exists purely as defense against real-world delivery jitter
	// on execute_transition across members, not because the protocol asks
	// for it.
	//
	// Cleared lazily by selectSendRatchetLocked when the TTL elapses; that
	// call also resets sendCounter so the new ratchet starts from nonce 0
	// per spec ("When a key ratchet is generated for a new epoch, the
	// sender resets their nonce to 0").
	retainedSendRatchet   *mediakeys.KeyRatchet
	retainedSendExpiresAt time.Time
	sendRetentionTTL      time.Duration

	// sendCipher caches the AES-GCM cipher to avoid recreating it on every frame.
	// Invalidated when the ratchet key changes (~every 16 frames per DAVE spec).
	sendCipher    cipher.AEAD
	sendCipherKey []byte // copy of the key used to create sendCipher

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

	epochReady chan struct{}

	// recoveryAttempts counts consecutive invalidate → new key package cycles
	// without an activated epoch; bounded by maxRecoveryAttempts.
	recoveryAttempts int
	recoveryTimeout  time.Duration

	stats         Stats
	degradedSince time.Time

	// shutdown lifecycle
	//nolint:containedctx // intentional: the session owns its shutdown so Close can cancel the watchdogs; not a request-scoped ctx.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	shutdownOnce   sync.Once
	shutdownDone   chan struct{}
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
	replay   antiReplayWindow
}

// config collects construction-time settings; it only exists so Options have
// something to mutate before the Session is built.
type config struct {
	logger           *slog.Logger
	recoveryTimeout  time.Duration
	sendRetentionTTL time.Duration
	hook             func(*Session)
}

// Option configures a Session at construction time. Pass Options to New, or
// to CreateFunc to have them applied to every session the voice layer creates.
type Option func(*config)

// WithLogger sets the logger the session binds its correlation fields
// (dave_session, user_id, channel_id) onto. Defaults to slog.Default().
// A nil logger is ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithRecoveryTimeout sets how long the recovery and commit-confirm watchdogs
// wait for an epoch to activate before declaring the MLS state broken and
// re-requesting a key package (protocol.md "Recovery from Invalid Commit or
// Welcome"). Defaults to 15s. Values <= 0 are ignored.
func WithRecoveryTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.recoveryTimeout = d
		}
	}
}

// WithSessionHook registers a function called with the fully constructed
// *Session before it is handed to the voice layer. This is the way to get a
// handle on sessions the voice layer creates internally (via CreateFunc):
// stash the *Session to read State()/Stats(), gate audio on ShouldHoldFrames,
// and call Close() when your disconnect handling discards the connection.
func WithSessionHook(hook func(*Session)) Option {
	return func(c *config) {
		c.hook = hook
	}
}

// New creates a DAVE session for one voice connection. The returned *Session
// implements godave.Session, so it can be handed to the voice layer directly;
// keep the concrete reference for observability and lifecycle (see the
// Session type docs). Most disgo integrators want CreateFunc instead, which
// adapts New to the voice manager's factory signature.
func New(userID godave.UserID, callbacks godave.Callbacks, opts ...Option) *Session {
	cfg := config{
		logger:           slog.Default(),
		recoveryTimeout:  epochRecoveryTimeout,
		sendRetentionTTL: epochRetention,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	id := newSessionID()

	ctx, cancel := context.WithCancel(context.Background())

	sess := &Session{
		logger:           cfg.logger.With("dave_session", id, "user_id", string(userID)),
		baseLogger:       cfg.logger,
		id:               id,
		userID:           userID,
		callbacks:        callbacks,
		ssrcCodecs:       make(map[uint32]codecs.Kind),
		users:            make(map[godave.UserID]struct{}),
		sendCounter:      mediakeys.NewNonceCounter(),
		sendRetentionTTL: cfg.sendRetentionTTL,
		epochReady:       make(chan struct{}),
		recoveryTimeout:  cfg.recoveryTimeout,
		shutdownCtx:      ctx,
		shutdownCancel:   cancel,
		shutdownDone:     make(chan struct{}),
	}

	if cfg.hook != nil {
		cfg.hook(sess)
	}

	return sess
}

// CreateFunc adapts New to godave.SessionCreateFunc so the voice layer can
// create one session per voice connection. The logger the voice layer passes
// in is used unless overridden with WithLogger.
//
// Example:
//
//	voice.WithDaveSessionCreateFunc(session.CreateFunc(
//	    session.WithSessionHook(func(s *session.Session) {
//	        // stash s keyed by guild/conn: read s.State() for health,
//	        // gate audio on s.ShouldHoldFrames(), and s.Close() on discard.
//	    }),
//	))
func CreateFunc(opts ...Option) godave.SessionCreateFunc {
	return func(logger *slog.Logger, userID godave.UserID, callbacks godave.Callbacks) godave.Session {
		return New(userID, callbacks, append([]Option{WithLogger(logger)}, opts...)...)
	}
}

// newSessionID returns a short random hex id used to correlate every log line of
// a single DAVE session. It's random rather than a counter so ids don't collide
// across restarts or instances, and a move/recovery (which creates a fresh
// session for the same channel) gets a distinct id.
func newSessionID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}

	return hex.EncodeToString(b[:])
}

func (s *Session) MaxSupportedProtocolVersion() int {
	return 1
}

func (s *Session) SetChannelID(channelID godave.ChannelID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channelID = channelID
	// Re-bind from baseLogger so the channel_id rides on every subsequent log
	// line while preserving whatever fields the integrator bound (e.g. guild_id).
	s.logger = s.baseLogger.With(
		"dave_session", s.id,
		"user_id", string(s.userID),
		"channel_id", uint64(channelID),
	)
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
	// Close the old channel so any goroutine blocked on it wakes up immediately.
	select {
	case <-s.epochReady:
	default:
		close(s.epochReady)
	}
	s.epochReady = make(chan struct{})
}

// selectSendRatchetLocked returns the ratchet to use for the next Encrypt
// frame. During the transition window (between a new epoch activating and
// sendRetentionTTL elapsing), the previous (retained) ratchet is used so
// receivers that haven't yet caught up to the new commit can still decrypt
// frames the sender emits during the gap — see the retainedSendRatchet field
// doc for why this is a defensive extension beyond the literal protocol text,
// not a spec requirement. When the retained ratchet expires, this resets
// sendCounter (so the new ratchet starts from nonce 0 per spec) and returns
// the new ratchet. Must be called with s.mu held.
func (s *Session) selectSendRatchetLocked() *mediakeys.KeyRatchet {
	if s.retainedSendRatchet != nil {
		if time.Now().Before(s.retainedSendExpiresAt) {
			return s.retainedSendRatchet
		}
		s.sendCounter.Reset()
		s.retainedSendRatchet = nil
		s.retainedSendExpiresAt = time.Time{}
	}

	return s.sendRatchet
}

func (s *Session) signalEpochReadyLocked() {
	select {
	case <-s.epochReady:
		return
	default:
		close(s.epochReady)
	}
}

func (s *Session) Encrypt(ssrc uint32, frameData []byte, encryptedFrame []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// No E2EE ratchet available: forward the frame unmodified instead of
	// failing, so the audio stream keeps advancing. This covers a fresh
	// session (no ratchet yet), a protocol-version-0 (transport-only)
	// session, and the rare case where both the active and retained
	// ratchets are gone. Receivers see no DAVE marker and pass it through
	// too. Mirrors libdave's default passthrough mode (protocol.md
	// "Passthrough Mode"). Note: a nil activeEpoch is OK as long as the
	// retained ratchet is set — that's the post-reset transition window
	// before the new epoch activates.
	ratchet := s.selectSendRatchetLocked()
	if ratchet == nil {
		s.stats.PassthroughFrames++

		return copy(encryptedFrame, frameData), nil
	}

	// Track frames sent via the retained ratchet during the transition
	// window (useful for observability).
	if s.retainedSendRatchet != nil {
		s.stats.TransitionFrames++
	}

	kind, ok := s.ssrcCodecs[ssrc]
	if !ok {
		return 0, fmt.Errorf("%w: %d", ErrNoCodecForSSRC, ssrc)
	}
	if kind == codecs.CodecUnknown {
		kind = codecs.CodecOpus
	}

	fullNonce, truncatedNonce, generation := s.sendCounter.Next()
	key, err := ratchet.GetKey(generation)
	if err != nil {
		s.stats.EncryptFailures++

		return 0, err
	}
	// Our own send counter is monotonic and trusted, so commit the ratchet to
	// this generation. This keeps the ratchet's base tracking the send position
	// (bounding future GetKey walks) instead of relying on GetKey to advance it.
	ratchet.Commit(generation)

	// Reuse the AES-GCM cipher if the key hasn't changed (hot path: same generation).
	// The ratchet key changes every ~16 frames; recreation is infrequent.
	if !bytes.Equal(s.sendCipherKey, key) {
		newCipher, cipherErr := frame.NewGCM8(key)
		if cipherErr != nil {
			s.stats.EncryptFailures++

			return 0, fmt.Errorf("cipher creation: %w", cipherErr)
		}
		s.sendCipher = newCipher
		s.sendCipherKey = append(s.sendCipherKey[:0], key...)
	}

	// H264/H265 may need to retry with nonce+1 if the output contains start code sequences.
	// That path reconstructs the cipher internally, so fall back to EncryptInto for those codecs.
	var n int
	if kind == codecs.CodecH264 || kind == codecs.CodecH265 {
		n, err = codecs.EncryptInto(kind, encryptedFrame, frameData, key, truncatedNonce)
	} else {
		n, err = codecs.EncryptWithCipherInto(kind, encryptedFrame, frameData, s.sendCipher, truncatedNonce)
	}
	if err != nil {
		s.stats.EncryptFailures++

		return 0, err
	}

	// activeEpoch may be nil during the post-reset transition window when
	// we're encrypting with the retained ratchet; log 0 in that case.
	epochID := uint64(0)
	if s.activeEpoch != nil {
		epochID = s.activeEpoch.id
	}
	s.logger.Debug("frame encrypted",
		"ssrc", ssrc,
		"epoch", epochID,
		"retained", s.retainedSendRatchet != nil,
		"nonce", fullNonce,
		"generation", generation,
		"plaintext_size", len(frameData),
		"encrypted_size", n)

	return n, nil
}

func (s *Session) MaxDecryptedFrameSize(_ godave.UserID, frameSize int) int {
	return frameSize
}

func (s *Session) Decrypt(userID godave.UserID, frameData []byte, decryptedFrame []byte) (int, error) {
	// Full lock (not RLock): Decrypt mutates per-sender state — the nonce
	// expander (Commit) and the anti-replay window (checkAndMark) — which are
	// not safe under concurrent readers. Encrypt already holds a full lock, so
	// this keeps both media paths consistently serialized per session.
	s.mu.Lock()
	defer s.mu.Unlock()

	if !frame.LooksLikeDAVEFrame(frameData) {
		// Under active E2EE, a non-DAVE frame is a plaintext injection and is
		// rejected (only the silence packet is allowed through). But once the
		// session has been downgraded to transport-only (protocolVersion 0),
		// passthrough is the expected mode again — even while activeEpoch is
		// still retained to decrypt in-flight DAVE frames from before the
		// downgrade — so v0 plaintext frames must pass through.
		if s.activeEpoch != nil && s.protocolVersion != 0 && !isSilencePacket(frameData) {
			return 0, ErrDecryptionFailed
		}
		n := copy(decryptedFrame, frameData)

		return n, nil
	}

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

		// Tentative expansion — does NOT mutate highestSeen. The advance is
		// committed only after frame authentication succeeds, so a forged
		// frame can't poison the expander state.
		fullNonce := sender.expander.ExpandTentative(parsed.TruncatedNonce)
		generation := uint32(fullNonce >> 24)

		// Bounded generation jump — rejects forged nonces that target a
		// generation far ahead of the current one (CPU DoS guard).
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

		// Authentication succeeded — now advance the expander, the ratchet base,
		// and check anti-replay. All three MUST happen only after GCM tag
		// verification, so a forged frame can't poison the expander state,
		// drive the ratchet forward, or be accepted as a replay.
		sender.expander.Commit(fullNonce)
		sender.ratchet.Commit(generation)
		if !sender.replay.checkAndMark(fullNonce) {
			s.stats.RejectedReplayFrames++
			lastErr = ErrDecryptionFailed

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
		// select_protocol_ack always marks a new voice connection — reset all
		// group state so stale data from a previous channel cannot block
		// re-creation of the MLS group on the new connection.
		s.activeEpoch = nil
		s.pendingEpoch = nil
		s.retainedEpoch = nil
		s.groupID = nil
		s.pendingGroupID = nil
		s.pendingCommitBytes = nil
		s.preCommitGroupState = nil
		s.proposalQueue = nil
		s.resetEpochReadyLocked()
		// Keep the send ratchet (and counter) alive through the transition
		// window (defensive padding, not spec-mandated — see retainedSendRatchet
		// field doc): any in-flight frame encrypted with the old key is still
		// decryptable by receivers in the same group who have it in their
		// retained list. selectSendRatchetLocked will reset the counter when
		// sendRetentionTTL elapses.
		if s.sendRatchet != nil {
			s.retainedSendRatchet = s.sendRatchet
			s.retainedSendExpiresAt = time.Now().Add(s.sendRetentionTTL)
			s.stats.TransitionWindows++
		}
		s.sendRatchet = nil

		s.pendingKeyPackage = nil
		s.mlsClient = nil
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

	// transition_id 0 is the DAVE "Sole member reset" / initial transition: it is
	// executed immediately and is never acknowledged with ready_for_transition.
	// No commit or welcome arrives in this case, so we must transition to our own
	// sole-member local group here, deriving our send ratchet so the bot keeps
	// encrypting while alone (protocol.md "Sole member reset").
	if transitionID == 0 {
		s.activeTransitionID = 0
		s.activateSoleMemberEpochLocked()
		s.pendingTransitionID = 0

		return
	}

	// Downgrade to v0 (protocol.md:124-125): no commit or welcome will arrive,
	// so the normal op23 path (from OnDaveMLSPrepareCommitTransition /
	// OnDaveMLSWelcome) never fires. Send ready_for_transition immediately.
	if protocolVersion == 0 && s.callbacks != nil {
		s.logger.Debug("downgrade to v0: sending ready_for_transition",
			"transition_id", transitionID)
		if err := s.retrySend(func() error {
			return s.callbacks.SendReadyForTransition(transitionID)
		}); err != nil {
			s.logger.Error("failed to send ready_for_transition",
				"transition_id", transitionID, "error", err)
		}
	}
}

func (s *Session) OnDaveExecuteTransition(transitionID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Debug("OnDaveExecuteTransition",
		"transition_id", transitionID,
		"protocol_version", s.protocolVersion,
		"pending_epoch_set", s.pendingEpoch != nil)
	s.activeTransitionID = transitionID

	// Downgrade to v0 (protocol.md:129): immediately clear the send-side
	// so Encrypt falls back to passthrough. Keep activeEpoch for
	// receive-side retention (in-flight DAVE frames from before the
	// transition).
	if s.protocolVersion == 0 {
		s.stats.DowngradeToV0++
		s.sendRatchet = nil
		s.retainedSendRatchet = nil
		s.retainedSendExpiresAt = time.Time{}
		s.sendCipher = nil
		s.sendCipherKey = nil
		s.pendingEpoch = nil
		s.pendingGroupID = nil
		s.pendingCommitBytes = nil
		s.preCommitGroupState = nil
		s.groupID = nil
		s.resetEpochReadyLocked()
		s.logger.Debug("downgrade to v0 executed: send-side cleared to passthrough",
			"transition_id", transitionID)

		return
	}

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
	// Same as OnSelectProtocolAck: keep the send ratchet alive through
	// the transition window so receivers with the OLD key can still
	// decrypt in-flight frames (defensive padding, not spec-mandated —
	// see retainedSendRatchet field doc).
	if s.sendRatchet != nil {
		s.retainedSendRatchet = s.sendRatchet
		s.retainedSendExpiresAt = time.Now().Add(s.sendRetentionTTL)
		s.stats.TransitionWindows++
	}
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
	s.logger.Debug("OnDaveMLSProposals",
		"size", len(proposals),
		"group_id", fmt.Sprintf("%x", s.groupID),
		"has_group", len(s.groupID) > 0)

	// If a pendingEpoch is already waiting for ExecuteTransition, queue this
	// batch instead of committing immediately. Committing again would advance
	// the local group state past what Discord DS has accepted, causing the
	// intermediate epoch to be overwritten and audio keys to diverge.
	if s.pendingEpoch != nil {
		s.logger.Debug("OnDaveMLSProposals: pendingEpoch in flight, queuing proposals", "queue_len", len(s.proposalQueue)+1)
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
	acceptedAny, err := s.processProposalBatchLocked(proposals)
	if err != nil {
		s.logger.Error("failed to process proposals", "error", err, "size", len(proposals))

		return
	}
	if len(s.groupID) == 0 {
		s.logger.Warn("no MLS group after processing proposals, skipping commit")

		return
	}
	// DAVE revoke (operation_type=1) solo quita proposals cacheados; la spec
	// manda commitear "if there are one or more cached proposals after
	// processing" (protocol.md:176) — un revoke puro no deja proposals nuevos.
	if len(proposals) > 0 && proposals[0] == 1 {
		s.logger.Info("mls revoke processed, no commit needed",
			"size", len(proposals))

		return
	}
	if !acceptedAny {
		s.logger.Info("mls proposals processed without accepted append proposals, skipping commit",
			"size", len(proposals))

		return
	}
	if err := s.commitProposalsLocked(); err != nil {
		s.logger.Error("failed to commit proposals", "error", err)

		return
	}
	s.logger.Info("mls proposals processed and committed",
		"size", len(proposals),
		"pending_epoch_set", s.pendingEpoch != nil,
		"pending_epoch_id", func() uint64 {
			if s.pendingEpoch != nil {
				return s.pendingEpoch.id
			}

			return 0
		}())
}

// reconcileCompetingCommitLocked handles the case where the DS echoed a commit
// that is not ours: it rolls back any pending (lost) commit to the pre-commit
// snapshot and then processes the winning commit. It returns false if the
// transition must be aborted because the state restore or the commit processing
// failed. Must be called with s.mu held.
func (s *Session) reconcileCompetingCommitLocked(transitionID uint16, commitMessage []byte) bool {
	if s.pendingEpoch != nil {
		// Our commit lost; restore pre-commit state before processing the winner.
		s.logger.Debug("OnDaveMLSPrepareCommitTransition: competing commit won, rolling back",
			"transition_id", transitionID,
			"our_commit_size", len(s.pendingCommitBytes),
			"winning_commit_size", len(commitMessage))
		if err := s.restorePreCommitStateLocked(); err != nil {
			s.logger.Error("failed to restore pre-commit state", "transition_id", transitionID, "error", err)
			if s.callbacks != nil {
				_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
			}

			return false
		}
	}

	if err := s.processCommitLocked(commitMessage); err != nil {
		s.stats.CommitsFailed++
		s.logger.Error("failed to process commit", "transition_id", transitionID, "error", err)
		if s.callbacks != nil {
			_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
		}
		s.invalidateAndResendKeyPackageLocked()

		return false
	}
	s.stats.CommitsProcessed++

	return true
}

func (s *Session) OnDaveMLSPrepareCommitTransition(transitionID uint16, commitMessage []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Debug("OnDaveMLSPrepareCommitTransition",
		"transition_id", transitionID,
		"commit_size", len(commitMessage),
		"pending_epoch_set", s.pendingEpoch != nil,
		"commit_hex_prefix", fmt.Sprintf("%x", commitMessage[:minInt(32, len(commitMessage))]))
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
	} else if !s.reconcileCompetingCommitLocked(transitionID, commitMessage) {
		return
	}

	// transition_id 0 is executed immediately and is not acknowledged; only send
	// ready_for_transition for real (non-initial) transitions (matches golibdave).
	if transitionID != 0 && s.callbacks != nil {
		if err := s.retrySend(func() error { return s.callbacks.SendReadyForTransition(transitionID) }); err != nil {
			s.logger.Error("failed to send ready for transition", "transition_id", transitionID, "error", err)
		}
	}

	if transitionID == 0 {
		s.logger.Debug("activating epoch immediately for initial transition (transitionID=0)")
		s.activeTransitionID = 0
		s.activatePendingEpochLocked()
		s.pendingTransitionID = 0
	}
}

func (s *Session) OnDaveMLSWelcome(transitionID uint16, welcomeMessage []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Debug("OnDaveMLSWelcome", "transition_id", transitionID, "welcome_size", len(welcomeMessage))
	s.pendingTransitionID = transitionID

	// If we have a pending epoch it means we previously committed. A Welcome
	// arriving means Discord DS chose another member's commit over ours — our
	// commit was rejected. Roll back our local state to the pre-commit snapshot
	// so that joinPendingWelcomeLocked operates from the correct epoch.
	if s.pendingEpoch != nil {
		s.logger.Debug("OnDaveMLSWelcome: our commit was rejected by DS (Welcome received), rolling back",
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
		s.stats.WelcomesFailed++
		s.logger.Error("failed to join welcome", "transition_id", transitionID, "error", err)
		if s.callbacks != nil {
			_ = s.callbacks.SendInvalidCommitWelcome(transitionID)
		}
		s.invalidateAndResendKeyPackageLocked()

		return
	}
	s.stats.WelcomesJoined++
	s.logger.Debug("OnDaveMLSWelcome: joined successfully",
		"pending_epoch_set", s.pendingEpoch != nil,
		"pending_epoch_id", func() uint64 {
			if s.pendingEpoch != nil {
				return s.pendingEpoch.id
			}

			return 0
		}())

	// transition_id 0 is executed immediately and is not acknowledged; only send
	// ready_for_transition for real (non-initial) transitions (matches golibdave).
	if transitionID != 0 && s.callbacks != nil {
		if err := s.retrySend(func() error { return s.callbacks.SendReadyForTransition(transitionID) }); err != nil {
			s.logger.Error("failed to send ready for transition", "transition_id", transitionID, "error", err)
		}
	}

	if transitionID == 0 {
		s.logger.Debug("activating epoch immediately from welcome (transitionID=0)")
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

// isSilencePacket reports whether frameData is exactly the 3-byte SFU silence
// packet (0xF8FFFE) the spec allows through even under active E2EE
// (protocol.md:633-641). Compared byte-by-byte to avoid allocating a literal
// slice on every call.
func isSilencePacket(frameData []byte) bool {
	return len(frameData) == 3 &&
		frameData[0] == 0xF8 && frameData[1] == 0xFF && frameData[2] == 0xFE
}
