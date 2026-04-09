package session

import "errors"

var (
	ErrNoActiveEpoch = errors.New("session: no active epoch")

	ErrDecryptionFailed = errors.New("session: decryption failed")
)
