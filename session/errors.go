package session

import "errors"

var (
	ErrNoActiveEpoch = errors.New("session: no active epoch")

	ErrDecryptionFailed = errors.New("session: decryption failed")

	ErrNilExporterStore          = errors.New("session: mls exporter store is nil")
	ErrExporterSecretUnavailable = errors.New("session: exporter secret not available")
	ErrInvalidCredentialIdentity = errors.New("session: invalid credential identity length")
	ErrNoActiveGroup             = errors.New("session: no active group")
	ErrInvalidVectorLength       = errors.New("session: invalid TLS vector length encoding")
	ErrProposalsTooShort         = errors.New("session: proposals payload too short")
	ErrProposalsTruncated        = errors.New("session: proposals vector truncated")
	ErrProposalTooShort          = errors.New("session: proposal too short")
	ErrEmptyProposal             = errors.New("session: empty marshaled proposal")
	ErrNoExternalSender          = errors.New("session: no external sender package available")
	ErrNoPreCommitState          = errors.New("session: no pre-commit state to restore")
	ErrExpectedWelcome           = errors.New("session: expected Welcome in MLSMessage")
	ErrNoCodecForSSRC            = errors.New("session: no codec assigned for ssrc")
)
