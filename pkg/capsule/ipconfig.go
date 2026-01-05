package capsule

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

// AddressAssignment represents a single IP address assignment.
// RFC 9484 Section 5.1.1: https://www.rfc-editor.org/rfc/rfc9484.html#section-5.1.1
type AddressAssignment struct {
	RequestID    uint64  // Request ID (matches ADDRESS_REQUEST)
	IPVersion    uint8   // 4 for IPv4, 6 for IPv6
	IPAddress    net.IP  // Assigned IP address
	PrefixLength uint8   // Prefix length (e.g., 32 for /32, 24 for /24)
}

// AddressAssignCapsule represents an ADDRESS_ASSIGN capsule (Type 0x01).
// RFC 9484 Section 5.1.1
type AddressAssignCapsule struct {
	Assignments []AddressAssignment
}

// Encode encodes the AddressAssignCapsule into a Capsule.
func (c *AddressAssignCapsule) Encode() (*Capsule, error) {
	if c == nil {
		return nil, fmt.Errorf("AddressAssignCapsule is nil")
	}

	var buf bytes.Buffer

	// Write Assigned Address Count (varint)
	countBytes, _ := EncodeVarint(uint64(len(c.Assignments)))
	buf.Write(countBytes)

	// Write each assignment
	for i, assign := range c.Assignments {
		// Validate IP version
		if assign.IPVersion != 4 && assign.IPVersion != 6 {
			return nil, fmt.Errorf("assignment #%d: invalid IP version %d (must be 4 or 6)", i, assign.IPVersion)
		}

		// Validate IP address length
		var ipBytes []byte
		if assign.IPVersion == 4 {
			ip4 := assign.IPAddress.To4()
			if ip4 == nil {
				return nil, fmt.Errorf("assignment #%d: IPv4 address required but got %v", i, assign.IPAddress)
			}
			ipBytes = []byte(ip4)
		} else { // IPv6
			ip6 := assign.IPAddress.To16()
			if ip6 == nil {
				return nil, fmt.Errorf("assignment #%d: IPv6 address required but got %v", i, assign.IPAddress)
			}
			// Ensure it's not an IPv4-mapped IPv6 address when IPVersion=6
			if ip4 := assign.IPAddress.To4(); ip4 != nil {
				return nil, fmt.Errorf("assignment #%d: IPv6 address required but got IPv4 %v", i, assign.IPAddress)
			}
			ipBytes = []byte(ip6)
		}

		// Request ID (varint)
		requestIDBytes, _ := EncodeVarint(assign.RequestID)
		buf.Write(requestIDBytes)

		// IP Version (varint)
		ipVersionBytes, _ := EncodeVarint(uint64(assign.IPVersion))
		buf.Write(ipVersionBytes)

		// IP Address (4 or 16 bytes, no length prefix per RFC 9484)
		buf.Write(ipBytes)

		// IP Prefix Length (1 byte, not varint per RFC 9484)
		buf.WriteByte(assign.PrefixLength)
	}

	return &Capsule{
		Type:   CapsuleTypeAddressAssign,
		Length: uint64(buf.Len()),
		Value:  buf.Bytes(),
	}, nil
}

// DecodeAddressAssign decodes an ADDRESS_ASSIGN capsule.
func DecodeAddressAssign(cap *Capsule) (*AddressAssignCapsule, error) {
	if cap == nil {
		return nil, fmt.Errorf("capsule is nil")
	}
	if cap.Type != CapsuleTypeAddressAssign {
		return nil, fmt.Errorf("expected ADDRESS_ASSIGN (type %d), got type %d", CapsuleTypeAddressAssign, cap.Type)
	}

	r := bytes.NewReader(cap.Value)

	// Read Assigned Address Count
	count, _, err := DecodeVarint(r)
	if err != nil {
		return nil, fmt.Errorf("decode address count: %w", err)
	}

	result := &AddressAssignCapsule{
		Assignments: make([]AddressAssignment, 0, count),
	}

	// Read each assignment
	for i := uint64(0); i < count; i++ {
		var assign AddressAssignment

		// Request ID (varint)
		reqID, _, err := DecodeVarint(r)
		if err != nil {
			return nil, fmt.Errorf("decode assignment #%d request ID: %w", i, err)
		}
		assign.RequestID = reqID

		// IP Version (varint)
		ipVer, _, err := DecodeVarint(r)
		if err != nil {
			return nil, fmt.Errorf("decode assignment #%d IP version: %w", i, err)
		}
		if ipVer != 4 && ipVer != 6 {
			return nil, fmt.Errorf("assignment #%d: invalid IP version %d", i, ipVer)
		}
		assign.IPVersion = uint8(ipVer)

		// IP Address (4 or 16 bytes)
		var ipLen int
		if assign.IPVersion == 4 {
			ipLen = 4
		} else {
			ipLen = 16
		}

		ipBytes := make([]byte, ipLen)
		if _, err := io.ReadFull(r, ipBytes); err != nil {
			return nil, fmt.Errorf("read assignment #%d IP address: %w", i, err)
		}
		assign.IPAddress = net.IP(ipBytes)

		// IP Prefix Length (1 byte)
		prefixByte := make([]byte, 1)
		if _, err := io.ReadFull(r, prefixByte); err != nil {
			return nil, fmt.Errorf("read assignment #%d prefix length: %w", i, err)
		}
		assign.PrefixLength = prefixByte[0]

		result.Assignments = append(result.Assignments, assign)
	}

	return result, nil
}
