package capsule

import (
	"bytes"
	"fmt"
	"io"
)

// EncodeCapsule encodes a Capsule into bytes.
// RFC 9297 Section 3.1: Capsule {
//   Type (i),
//   Length (i),
//   Value (..),
// }
func EncodeCapsule(cap *Capsule) ([]byte, error) {
	if cap == nil {
		return nil, fmt.Errorf("capsule is nil")
	}

	// Validate Length matches Value
	if uint64(len(cap.Value)) != cap.Length {
		return nil, fmt.Errorf("capsule length mismatch: Length=%d, Value=%d bytes", cap.Length, len(cap.Value))
	}

	var buf bytes.Buffer

	// Encode Type (varint)
	typeBytes, _ := EncodeVarint(uint64(cap.Type))
	buf.Write(typeBytes)

	// Encode Length (varint)
	lengthBytes, _ := EncodeVarint(cap.Length)
	buf.Write(lengthBytes)

	// Write Value
	buf.Write(cap.Value)

	return buf.Bytes(), nil
}

// DecodeCapsule decodes a Capsule from an io.Reader.
// Returns the decoded Capsule or an error.
func DecodeCapsule(r io.Reader) (*Capsule, error) {
	// Decode Type
	capType, _, err := DecodeVarint(r)
	if err != nil {
		return nil, fmt.Errorf("decode capsule type: %w", err)
	}

	// Decode Length
	length, _, err := DecodeVarint(r)
	if err != nil {
		return nil, fmt.Errorf("decode capsule length: %w", err)
	}

	// Read Value
	value := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, value); err != nil {
			return nil, fmt.Errorf("read capsule value (%d bytes): %w", length, err)
		}
	}

	return &Capsule{
		Type:   CapsuleType(capType),
		Length: length,
		Value:  value,
	}, nil
}
