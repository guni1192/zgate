package capsule

import (
	"net"
	"testing"
)

// TestAddressAssignEncode tests encoding of ADDRESS_ASSIGN capsules.
func TestAddressAssignEncode(t *testing.T) {
	testCases := []struct {
		name   string
		capsule *AddressAssignCapsule
		wantErr bool
	}{
		{
			name: "single-ipv4",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    0,
						IPVersion:    4,
						IPAddress:    net.ParseIP("10.100.0.2"),
						PrefixLength: 32,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "single-ipv6",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    1,
						IPVersion:    6,
						IPAddress:    net.ParseIP("2001:db8::1"),
						PrefixLength: 128,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple-assignments",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    0,
						IPVersion:    4,
						IPAddress:    net.ParseIP("10.100.0.2"),
						PrefixLength: 32,
					},
					{
						RequestID:    1,
						IPVersion:    4,
						IPAddress:    net.ParseIP("10.100.0.3"),
						PrefixLength: 24,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty-assignments",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{},
			},
			wantErr: false,
		},
		{
			name: "invalid-ip-version",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    0,
						IPVersion:    5, // Invalid
						IPAddress:    net.ParseIP("10.100.0.2"),
						PrefixLength: 32,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ipv4-with-ipv6-address",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    0,
						IPVersion:    4,
						IPAddress:    net.ParseIP("2001:db8::1"), // IPv6 address with IPVersion=4
						PrefixLength: 32,
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "nil-capsule",
			capsule: nil,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.capsule.Encode()
			if (err != nil) != tc.wantErr {
				t.Errorf("Encode() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestAddressAssignRoundtrip tests encoding and decoding.
func TestAddressAssignRoundtrip(t *testing.T) {
	testCases := []struct {
		name       string
		capsule    *AddressAssignCapsule
	}{
		{
			name: "single-ipv4-32",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    0,
						IPVersion:    4,
						IPAddress:    net.ParseIP("10.100.0.2"),
						PrefixLength: 32,
					},
				},
			},
		},
		{
			name: "single-ipv4-24",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    5,
						IPVersion:    4,
						IPAddress:    net.ParseIP("192.168.1.10"),
						PrefixLength: 24,
					},
				},
			},
		},
		{
			name: "single-ipv6",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    10,
						IPVersion:    6,
						IPAddress:    net.ParseIP("2001:db8::1"),
						PrefixLength: 128,
					},
				},
			},
		},
		{
			name: "multiple-mixed",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{
					{
						RequestID:    0,
						IPVersion:    4,
						IPAddress:    net.ParseIP("10.100.0.2"),
						PrefixLength: 32,
					},
					{
						RequestID:    1,
						IPVersion:    6,
						IPAddress:    net.ParseIP("2001:db8::2"),
						PrefixLength: 64,
					},
				},
			},
		},
		{
			name: "zero-assignments",
			capsule: &AddressAssignCapsule{
				Assignments: []AddressAssignment{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded, err := tc.capsule.Encode()
			if err != nil {
				t.Fatalf("Encode() failed: %v", err)
			}

			// Verify capsule type
			if encoded.Type != CapsuleTypeAddressAssign {
				t.Errorf("Type = %d, expected %d", encoded.Type, CapsuleTypeAddressAssign)
			}

			// Decode
			decoded, err := DecodeAddressAssign(encoded)
			if err != nil {
				t.Fatalf("DecodeAddressAssign() failed: %v", err)
			}

			// Verify assignment count
			if len(decoded.Assignments) != len(tc.capsule.Assignments) {
				t.Errorf("Assignment count = %d, expected %d", len(decoded.Assignments), len(tc.capsule.Assignments))
			}

			// Verify each assignment
			for i, expected := range tc.capsule.Assignments {
				actual := decoded.Assignments[i]

				if actual.RequestID != expected.RequestID {
					t.Errorf("Assignment #%d: RequestID = %d, expected %d", i, actual.RequestID, expected.RequestID)
				}
				if actual.IPVersion != expected.IPVersion {
					t.Errorf("Assignment #%d: IPVersion = %d, expected %d", i, actual.IPVersion, expected.IPVersion)
				}
				if !actual.IPAddress.Equal(expected.IPAddress) {
					t.Errorf("Assignment #%d: IPAddress = %v, expected %v", i, actual.IPAddress, expected.IPAddress)
				}
				if actual.PrefixLength != expected.PrefixLength {
					t.Errorf("Assignment #%d: PrefixLength = %d, expected %d", i, actual.PrefixLength, expected.PrefixLength)
				}
			}
		})
	}
}

// TestDecodeAddressAssignErrors tests error cases for DecodeAddressAssign.
func TestDecodeAddressAssignErrors(t *testing.T) {
	testCases := []struct {
		name    string
		capsule *Capsule
		wantErr bool
	}{
		{
			name:    "nil-capsule",
			capsule: nil,
			wantErr: true,
		},
		{
			name: "wrong-type",
			capsule: &Capsule{
				Type:   CapsuleTypeIPPacket,
				Length: 0,
				Value:  []byte{},
			},
			wantErr: true,
		},
		{
			name: "truncated-count",
			capsule: &Capsule{
				Type:   CapsuleTypeAddressAssign,
				Length: 0,
				Value:  []byte{},
			},
			wantErr: true,
		},
		{
			name: "invalid-ip-version",
			capsule: &Capsule{
				Type:   CapsuleTypeAddressAssign,
				Length: 3,
				Value:  []byte{0x01, 0x00, 0x05}, // Count=1, RequestID=0, IPVersion=5 (invalid)
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeAddressAssign(tc.capsule)
			if (err != nil) != tc.wantErr {
				t.Errorf("DecodeAddressAssign() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestNewIPPacketCapsule tests the IP_PACKET helper function.
func TestNewIPPacketCapsule(t *testing.T) {
	testCases := []struct {
		name   string
		packet []byte
	}{
		{"empty", []byte{}},
		{"small", []byte{0x45, 0x00, 0x00, 0x1C}},
		{"mtu", make([]byte, 1300)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cap := NewIPPacketCapsule(tc.packet)

			if cap.Type != CapsuleTypeIPPacket {
				t.Errorf("Type = %d, expected %d", cap.Type, CapsuleTypeIPPacket)
			}
			if cap.Length != uint64(len(tc.packet)) {
				t.Errorf("Length = %d, expected %d", cap.Length, len(tc.packet))
			}
			if len(cap.Value) != len(tc.packet) {
				t.Errorf("Value length = %d, expected %d", len(cap.Value), len(tc.packet))
			}
		})
	}
}
