package frame

import "errors"

var (
	ErrFrameTooShort           = errors.New("dave frame too short")
	ErrInvalidMagicMarker      = errors.New("invalid dave magic marker")
	ErrInvalidSupplementalSize = errors.New("invalid supplemental size")
	ErrInvalidULEB128          = errors.New("invalid uleb128 encoding")
	ErrInvalidRanges           = errors.New("invalid unencrypted ranges")
	ErrInvalidKeyLength        = errors.New("invalid AES-128 key length (must be 16 bytes)")
	ErrAuthTagMismatch         = errors.New("authentication failed")
)
