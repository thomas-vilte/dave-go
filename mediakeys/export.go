package mediakeys

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	ExporterLabel       = "Discord Secure Frames v0"
	BaseSecretLen       = 16
	MediaKeyLen         = 16
	DefaultRetentionTTL = 10 * time.Second
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
		return nil, fmt.Errorf("derive sender base secret: got %d bytes", len(secret))
	}

	return secret, nil
}
