package capsule

// NewIPPacketCapsule creates a new IP_PACKET capsule (Type 0x40).
// This is a convenience function for creating capsules that encapsulate IP packets.
func NewIPPacketCapsule(packet []byte) *Capsule {
	return &Capsule{
		Type:   CapsuleTypeIPPacket,
		Length: uint64(len(packet)),
		Value:  packet,
	}
}
