package mediakeys

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	ExporterLabel = "Discord Secure Frames v0"
	// BaseSecretLen is the required length of a sender base secret.
	BaseSecretLen = 16
	// MediaKeyLen is the required length of a derived media key.
	MediaKeyLen = 16
	// DefaultMaxGenerationGap is the maximum number of generations a single
	// GetKey call may advance the ratchet. Larger jumps are rejected to
	// prevent CPU DoS from forged nonces that target a far-ahead generation.
	DefaultMaxGenerationGap uint32 = 256
	DefaultRetentionTTL            = 10 * time.Second
)

type Exporter interface {
	Export(label string, ctx []byte, length int) ([]byte, error)
}

func SenderIDContextLE(senderID uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, senderID)

	return buf
}

func DeriveSenderBaseSecret(exporter Exporter, senderID uint64) ([]byte, error) {
	if exporter == nil {
		return nil, ErrNilExporter
	}

	secret, err := exporter.Export(ExporterLabel, SenderIDContextLE(senderID), BaseSecretLen)
	if err != nil {
		return nil, fmt.Errorf("derive sender base secret: %w", err)
	}

	if len(secret) != BaseSecretLen {
		return nil, fmt.Errorf("derive sender base secret: %w: got %d bytes", ErrInvalidBaseSecret, len(secret))
	}

	return secret, nil
}
