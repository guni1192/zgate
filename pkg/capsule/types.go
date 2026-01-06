package capsule

// CapsuleType represents a capsule type identifier.
// RFC 9297 Section 3.1: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.1
type CapsuleType uint64

// RFC 9297 Standard Capsule Types
const (
	// CapsuleTypeDatagram is used for HTTP Datagrams.
	// Not used in zgate (stream-based tunneling, not datagram).
	CapsuleTypeDatagram CapsuleType = 0x00
)

// RFC 9484 IP Proxying Capsule Types
// https://www.rfc-editor.org/rfc/rfc9484.html#section-5
const (
	// CapsuleTypeAddressAssign is sent from server to agent to assign Virtual IP.
	// RFC 9484 Section 5.1.1
	CapsuleTypeAddressAssign CapsuleType = 0x01

	// CapsuleTypeAddressRequest is sent from agent to server to request IP allocation.
	// RFC 9484 Section 5.1.2
	// Not implemented in current phase (static allocation via ADDRESS_ASSIGN).
	CapsuleTypeAddressRequest CapsuleType = 0x02

	// CapsuleTypeRouteAdvertisement is sent from server to agent to advertise routes.
	// RFC 9484 Section 5.2
	// Planned for Phase 3.3 (dynamic routing for SaaS vs on-prem).
	CapsuleTypeRouteAdvertisement CapsuleType = 0x03
)

// zgate Custom Capsule Types
// Private use range (>= 0x40) requires IANA registration for production.
// https://www.iana.org/assignments/masque/masque.xhtml#capsule-types
const (
	// CapsuleTypeIPPacket encapsulates raw IP packets for stream-based tunneling.
	// This is a zgate-specific type (not defined in RFC 9484).
	// IANA registration planned for Phase 3.3.
	CapsuleTypeIPPacket CapsuleType = 0x40

	// Reserved for future use:
	// CapsuleTypeSessionMetadata CapsuleType = 0x41 // Session info, statistics
	// CapsuleTypeACLNotification CapsuleType = 0x42 // ACL decision notification
	// CapsuleTypeKeepalive       CapsuleType = 0x43 // Tunnel keepalive
)

// Capsule represents a parsed capsule frame.
// RFC 9297 Section 3.1: Capsule {
//   Type (i),
//   Length (i),
//   Value (..),
// }
type Capsule struct {
	Type   CapsuleType
	Length uint64
	Value  []byte
}
