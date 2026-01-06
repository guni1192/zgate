// Package capsule implements RFC 9297 Capsule Protocol for HTTP.
package capsule

import (
	"encoding/binary"
	"fmt"
	"io"
)

// EncodeVarint encodes a uint64 value as a QUIC variable-length integer.
// RFC 9000 Section 16: https://www.rfc-editor.org/rfc/rfc9000.html#section-16
//
// Encoding:
//   - 00xxxxxx: 1 byte  (0-63)
//   - 01xxxxxx: 2 bytes (0-16383)
//   - 10xxxxxx: 4 bytes (0-1073741823)
//   - 11xxxxxx: 8 bytes (0-4611686018427387903)
//
// Returns the encoded bytes and the number of bytes written.
func EncodeVarint(value uint64) ([]byte, int) {
	switch {
	case value <= 0x3F: // 6 bits: 0-63
		return []byte{byte(value)}, 1

	case value <= 0x3FFF: // 14 bits: 0-16383
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(value)|0x4000)
		return buf, 2

	case value <= 0x3FFFFFFF: // 30 bits: 0-1073741823
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(value)|0x80000000)
		return buf, 4

	default: // 62 bits: 0-4611686018427387903
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, value|0xC000000000000000)
		return buf, 8
	}
}

// DecodeVarint decodes a QUIC variable-length integer from an io.Reader.
// RFC 9000 Section 16: https://www.rfc-editor.org/rfc/rfc9000.html#section-16
//
// Returns the decoded value, the number of bytes read, and any error encountered.
func DecodeVarint(r io.Reader) (uint64, int, error) {
	// Read first byte to determine length
	firstByte := make([]byte, 1)
	if _, err := io.ReadFull(r, firstByte); err != nil {
		return 0, 0, fmt.Errorf("read first byte: %w", err)
	}

	// Extract 2-bit prefix
	prefix := firstByte[0] >> 6

	switch prefix {
	case 0x00: // 1 byte total
		return uint64(firstByte[0] & 0x3F), 1, nil

	case 0x01: // 2 bytes total
		buf := make([]byte, 2)
		buf[0] = firstByte[0]
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, 1, fmt.Errorf("read 2-byte varint: %w", err)
		}
		value := binary.BigEndian.Uint16(buf) & 0x3FFF
		return uint64(value), 2, nil

	case 0x02: // 4 bytes total
		buf := make([]byte, 4)
		buf[0] = firstByte[0]
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, 1, fmt.Errorf("read 4-byte varint: %w", err)
		}
		value := binary.BigEndian.Uint32(buf) & 0x3FFFFFFF
		return uint64(value), 4, nil

	case 0x03: // 8 bytes total
		buf := make([]byte, 8)
		buf[0] = firstByte[0]
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, 1, fmt.Errorf("read 8-byte varint: %w", err)
		}
		value := binary.BigEndian.Uint64(buf) & 0x3FFFFFFFFFFFFFFF
		return value, 8, nil

	default:
		// This should never happen
		return 0, 1, fmt.Errorf("invalid varint prefix: %d", prefix)
	}
}
