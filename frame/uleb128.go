package frame

import "fmt"

func EncodeULEB128(value uint32) []byte {
	return appendULEB128(make([]byte, 0, 5), value)
}

// appendULEB128 appends the ULEB128 encoding of value to dst and returns the
// extended slice. Unlike EncodeULEB128, it doesn't allocate when dst has
// spare capacity (e.g. a stack-backed array in a hot path).
func appendULEB128(dst []byte, value uint32) []byte {
	for value >= 0x80 {
		dst = append(dst, 0x80|byte(value&0x7F))
		value >>= 7
	}

	return append(dst, byte(value))
}

func DecodeULEB128(data []byte) (value uint32, n int, err error) {
	if len(data) == 0 {
		return 0, 0, ErrInvalidULEB128
	}
	var shift uint
	for i := 0; i < len(data) && i < 5; i++ {
		b := data[i]
		value |= uint32(b&0x7F) << shift
		n = i + 1
		if b < 0x80 {
			return value, n, nil
		}
		shift += 7
		if shift >= 32 {
			return 0, 0, fmt.Errorf("uleb128 overflow: %w", ErrInvalidULEB128)
		}
	}

	return 0, 0, fmt.Errorf("truncated uleb128: %w", ErrInvalidULEB128)
}
