package ipam

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// allocator implements the Allocator interface.
type allocator struct {
	config       Config
	clientToIP   map[string]net.IP      // ClientID → VirtualIP
	ipToAlloc    map[string]*Allocation // IP string → Allocation details
	availableIPs []net.IP               // Pool of freed IPs for reuse
	nextIP       net.IP                 // Next sequential IP to allocate
	mu           sync.RWMutex           // Thread-safe access
}

// NewAllocator creates a new IPAM allocator.
func NewAllocator(config Config) (Allocator, error) {
	if config.Network == nil {
		return nil, fmt.Errorf("network is required")
	}
	if config.RelayIP == nil {
		return nil, fmt.Errorf("relay IP is required")
	}

	// Validate relay IP is within network
	if !config.Network.Contains(config.RelayIP) {
		return nil, fmt.Errorf("relay IP %s not in network %s", config.RelayIP, config.Network)
	}

	a := &allocator{
		config:       config,
		clientToIP:   make(map[string]net.IP),
		ipToAlloc:    make(map[string]*Allocation),
		availableIPs: []net.IP{},
		nextIP:       incrementIP(config.Network.IP),
	}

	return a, nil
}

// Allocate assigns a Virtual IP to a client (idempotent).
func (a *allocator) Allocate(clientID string) (net.IP, error) {
	if clientID == "" {
		return nil, fmt.Errorf("clientID is required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if client already has an allocation (idempotent)
	if ip, exists := a.clientToIP[clientID]; exists {
		// Update last seen timestamp
		if alloc, ok := a.ipToAlloc[ip.String()]; ok {
			alloc.LastSeenAt = time.Now()
		}
		return ip, nil
	}

	// Try to allocate from available pool first (reuse freed IPs)
	var ip net.IP
	if len(a.availableIPs) > 0 {
		ip = a.availableIPs[0]
		a.availableIPs = a.availableIPs[1:]
	} else {
		// Allocate next sequential IP
		ip = a.findNextAvailableIP()
		if ip == nil {
			return nil, fmt.Errorf("IP pool exhausted (all 253 IPs allocated)")
		}
	}

	// Create allocation
	now := time.Now()
	alloc := &Allocation{
		VirtualIP:   ip,
		ClientID:    clientID,
		AllocatedAt: now,
		LastSeenAt:  now,
	}

	a.clientToIP[clientID] = ip
	a.ipToAlloc[ip.String()] = alloc

	return ip, nil
}

// Release frees the IP allocated to a client.
func (a *allocator) Release(clientID string) error {
	if clientID == "" {
		return fmt.Errorf("clientID is required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	ip, exists := a.clientToIP[clientID]
	if !exists {
		return fmt.Errorf("no allocation found for client %s", clientID)
	}

	// Remove allocation
	delete(a.clientToIP, clientID)
	delete(a.ipToAlloc, ip.String())

	// Add IP back to available pool for reuse
	a.availableIPs = append(a.availableIPs, ip)

	return nil
}

// Refresh updates the last seen timestamp for a client.
func (a *allocator) Refresh(clientID string) error {
	if clientID == "" {
		return fmt.Errorf("clientID is required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	ip, exists := a.clientToIP[clientID]
	if !exists {
		return fmt.Errorf("no allocation found for client %s", clientID)
	}

	if alloc, ok := a.ipToAlloc[ip.String()]; ok {
		alloc.LastSeenAt = time.Now()
		return nil
	}

	return fmt.Errorf("allocation record missing for IP %s", ip)
}

// GetAllocation retrieves allocation info for a client.
func (a *allocator) GetAllocation(clientID string) (*Allocation, error) {
	if clientID == "" {
		return nil, fmt.Errorf("clientID is required")
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	ip, exists := a.clientToIP[clientID]
	if !exists {
		return nil, fmt.Errorf("no allocation found for client %s", clientID)
	}

	alloc, ok := a.ipToAlloc[ip.String()]
	if !ok {
		return nil, fmt.Errorf("allocation record missing for IP %s", ip)
	}

	// Return a copy to prevent external modification
	allocCopy := *alloc
	return &allocCopy, nil
}

// GetStats returns current IPAM statistics.
func (a *allocator) GetStats() Stats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	totalIPs := a.calculateTotalIPs()
	allocated := len(a.clientToIP)
	available := totalIPs - allocated

	return Stats{
		TotalIPs:     totalIPs,
		AllocatedIPs: allocated,
		AvailableIPs: available,
		ClientCount:  allocated,
	}
}

// Close releases resources.
func (a *allocator) Close() error {
	// In-memory only implementation - no persistence to save
	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear maps to help GC
	a.clientToIP = nil
	a.ipToAlloc = nil
	a.availableIPs = nil

	return nil
}

// findNextAvailableIP finds the next sequential IP that's not allocated or reserved.
func (a *allocator) findNextAvailableIP() net.IP {
	maxAttempts := 256 // Prevent infinite loop
	for i := 0; i < maxAttempts; i++ {
		// Check if nextIP is within network
		if !a.config.Network.Contains(a.nextIP) {
			return nil // Exhausted network range
		}

		// Skip relay IP
		if a.nextIP.Equal(a.config.RelayIP) {
			a.nextIP = incrementIP(a.nextIP)
			continue
		}

		// Skip broadcast address (last IP in subnet)
		if isBroadcast(a.nextIP, a.config.Network) {
			return nil // Reached broadcast, no more IPs
		}

		// Check if IP is already allocated
		ipStr := a.nextIP.String()
		if _, allocated := a.ipToAlloc[ipStr]; !allocated {
			ip := make(net.IP, len(a.nextIP))
			copy(ip, a.nextIP)
			a.nextIP = incrementIP(a.nextIP)
			return ip
		}

		a.nextIP = incrementIP(a.nextIP)
	}

	return nil
}

// calculateTotalIPs calculates total usable IPs in the network.
func (a *allocator) calculateTotalIPs() int {
	ones, bits := a.config.Network.Mask.Size()
	if bits == 0 {
		return 0
	}

	// Total IPs = 2^(bits - ones) - 2 (network + broadcast)
	// But we already skip network address in our allocation logic
	totalHosts := 1 << (bits - ones)

	// Subtract network address and broadcast address
	usableIPs := totalHosts - 2

	// For /24: 256 - 2 = 254 total hosts
	// But we also skip relay IP, so effectively 253 usable
	return usableIPs - 1 // -1 for relay IP
}

// incrementIP increments an IP address by 1.
func incrementIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] != 0 {
			break
		}
	}

	return newIP
}

// isBroadcast checks if an IP is the broadcast address of the network.
func isBroadcast(ip net.IP, network *net.IPNet) bool {
	// Broadcast is when all host bits are 1
	broadcast := make(net.IP, len(network.IP))
	for i := range network.IP {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}
