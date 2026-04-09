package frame

import "fmt"

func EncodeULEB128(value uint32) []byte {
	if value == 0 {
		return []byte{0}
	}
	var buf [5]byte
	n := 0
	for value >= 0x80 {
		buf[n] = 0x80 | byte(value&0x7F)
		n++
		value >>= 7
	}
	buf[n] = byte(value)
	n++
	return buf[:n]
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
