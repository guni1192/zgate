package ipam

import (
	"net"
	"time"
)

// Allocation represents an IP allocation to a client.
type Allocation struct {
	VirtualIP   net.IP
	ClientID    string
	AllocatedAt time.Time
	LastSeenAt  time.Time
}

// Config holds IPAM allocator configuration.
type Config struct {
	Network *net.IPNet // Virtual network CIDR (e.g., 10.100.0.0/24)
	RelayIP net.IP     // Relay's IP address to skip during allocation
	// NO LeaseTimeout or PersistPath (in-memory only per user choice)
}

// Stats provides IPAM statistics.
type Stats struct {
	TotalIPs     int // Total usable IPs in the network
	AllocatedIPs int // Currently allocated IPs
	AvailableIPs int // Available IPs (including released IPs in pool)
	ClientCount  int // Number of active clients
}

// Allocator is the interface for IP address management.
type Allocator interface {
	// Allocate assigns a Virtual IP to a client (idempotent).
	// Same clientID always gets the same IP during relay session.
	Allocate(clientID string) (net.IP, error)

	// Release frees the IP allocated to a client.
	Release(clientID string) error

	// Refresh updates the last seen timestamp for a client.
	Refresh(clientID string) error

	// GetAllocation retrieves allocation info for a client.
	GetAllocation(clientID string) (*Allocation, error)

	// GetStats returns current IPAM statistics.
	GetStats() Stats

	// Close releases resources (future: save state).
	Close() error
}
