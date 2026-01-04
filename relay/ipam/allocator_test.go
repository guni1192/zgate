package ipam

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewAllocator(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
	}{
		{
			name: "valid configuration",
			config: Config{
				Network: mustParseCIDR("10.100.0.0/24"),
				RelayIP: net.ParseIP("10.100.0.1"),
			},
			wantError: false,
		},
		{
			name: "missing network",
			config: Config{
				RelayIP: net.ParseIP("10.100.0.1"),
			},
			wantError: true,
		},
		{
			name: "missing relay IP",
			config: Config{
				Network: mustParseCIDR("10.100.0.0/24"),
			},
			wantError: true,
		},
		{
			name: "relay IP outside network",
			config: Config{
				Network: mustParseCIDR("10.100.0.0/24"),
				RelayIP: net.ParseIP("192.168.1.1"),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAllocator(tt.config)
			if (err != nil) != tt.wantError {
				t.Errorf("NewAllocator() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestAllocator_BasicAllocation(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	// First allocation should get 10.100.0.2 (skipping 10.100.0.1 relay IP)
	ip1, err := a.Allocate("client-1")
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	if ip1.String() != "10.100.0.2" {
		t.Errorf("Expected first IP to be 10.100.0.2, got %s", ip1.String())
	}

	// Second allocation should get 10.100.0.3
	ip2, err := a.Allocate("client-2")
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	if ip2.String() != "10.100.0.3" {
		t.Errorf("Expected second IP to be 10.100.0.3, got %s", ip2.String())
	}

	// Verify stats
	stats := a.GetStats()
	if stats.AllocatedIPs != 2 {
		t.Errorf("Expected 2 allocated IPs, got %d", stats.AllocatedIPs)
	}
	if stats.ClientCount != 2 {
		t.Errorf("Expected 2 clients, got %d", stats.ClientCount)
	}
}

func TestAllocator_IdempotentAllocation(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	clientID := "client-1"

	// First allocation
	ip1, err := a.Allocate(clientID)
	if err != nil {
		t.Fatalf("First Allocate() error = %v", err)
	}

	// Second allocation for same client should return same IP
	ip2, err := a.Allocate(clientID)
	if err != nil {
		t.Fatalf("Second Allocate() error = %v", err)
	}

	if !ip1.Equal(ip2) {
		t.Errorf("Allocate() not idempotent: first=%s, second=%s", ip1, ip2)
	}

	// Verify only one allocation exists
	stats := a.GetStats()
	if stats.AllocatedIPs != 1 {
		t.Errorf("Expected 1 allocated IP, got %d", stats.AllocatedIPs)
	}
}

func TestAllocator_ReleaseAndReuse(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	// Allocate to client-1
	ip1, err := a.Allocate("client-1")
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}

	// Release IP
	if err := a.Release("client-1"); err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	// Verify stats updated
	stats := a.GetStats()
	if stats.AllocatedIPs != 0 {
		t.Errorf("Expected 0 allocated IPs after release, got %d", stats.AllocatedIPs)
	}

	// Allocate to client-2 should reuse freed IP
	ip2, err := a.Allocate("client-2")
	if err != nil {
		t.Fatalf("Allocate() after release error = %v", err)
	}

	if !ip1.Equal(ip2) {
		t.Errorf("Expected IP reuse: first=%s, second=%s", ip1, ip2)
	}
}

func TestAllocator_SkipRelayIP(t *testing.T) {
	// Create allocator with relay IP at 10.100.0.2
	config := Config{
		Network: mustParseCIDR("10.100.0.0/24"),
		RelayIP: net.ParseIP("10.100.0.2"),
	}
	a, err := NewAllocator(config)
	if err != nil {
		t.Fatalf("NewAllocator() error = %v", err)
	}
	defer a.Close()

	// First allocation should get 10.100.0.1
	ip1, err := a.Allocate("client-1")
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	if ip1.String() != "10.100.0.1" {
		t.Errorf("Expected first IP to be 10.100.0.1, got %s", ip1.String())
	}

	// Second allocation should skip relay IP (10.100.0.2) and get 10.100.0.3
	ip2, err := a.Allocate("client-2")
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	if ip2.String() != "10.100.0.3" {
		t.Errorf("Expected second IP to be 10.100.0.3 (skipping relay IP 10.100.0.2), got %s", ip2.String())
	}

	// Verify relay IP is never allocated
	if ip1.Equal(config.RelayIP) || ip2.Equal(config.RelayIP) {
		t.Error("Relay IP was allocated to a client")
	}
}

func TestAllocator_PoolExhaustion(t *testing.T) {
	// Use smaller network for faster testing
	config := Config{
		Network: mustParseCIDR("10.100.0.0/29"), // Only 6 usable IPs
		RelayIP: net.ParseIP("10.100.0.1"),
	}
	a, err := NewAllocator(config)
	if err != nil {
		t.Fatalf("NewAllocator() error = %v", err)
	}
	defer a.Close()

	// /29 network: 10.100.0.0/29 has 8 IPs total
	// - 10.100.0.0 (network) - skipped by incrementIP starting from .1
	// - 10.100.0.1 (relay IP) - skipped
	// - 10.100.0.2-6 (usable) - 5 IPs
	// - 10.100.0.7 (broadcast) - skipped
	// So we can allocate 5 IPs

	allocated := 0
	for i := 1; i <= 10; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		_, err := a.Allocate(clientID)
		if err != nil {
			// Should fail after exhausting pool
			if allocated < 5 {
				t.Errorf("Allocation failed too early at client %d: %v", i, err)
			}
			break
		}
		allocated++
	}

	if allocated != 5 {
		t.Errorf("Expected to allocate 5 IPs before exhaustion, got %d", allocated)
	}

	// Verify error message
	_, err = a.Allocate("client-overflow")
	if err == nil {
		t.Error("Expected error on pool exhaustion, got nil")
	}
	if err.Error() != "IP pool exhausted (all 253 IPs allocated)" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestAllocator_ConcurrentAllocations(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	numClients := 100
	var wg sync.WaitGroup
	errors := make(chan error, numClients)
	ips := make(chan net.IP, numClients)

	// Allocate concurrently
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID string) {
			defer wg.Done()
			ip, err := a.Allocate(clientID)
			if err != nil {
				errors <- err
				return
			}
			ips <- ip
		}(fmt.Sprintf("client-%d", i))
	}

	wg.Wait()
	close(errors)
	close(ips)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent allocation error: %v", err)
	}

	// Verify unique IPs
	ipSet := make(map[string]bool)
	for ip := range ips {
		ipStr := ip.String()
		if ipSet[ipStr] {
			t.Errorf("Duplicate IP allocated: %s", ipStr)
		}
		ipSet[ipStr] = true
	}

	// Verify stats
	stats := a.GetStats()
	if stats.AllocatedIPs != numClients {
		t.Errorf("Expected %d allocated IPs, got %d", numClients, stats.AllocatedIPs)
	}
}

func TestAllocator_GetAllocation(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	clientID := "client-1"
	ip, err := a.Allocate(clientID)
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}

	// Get allocation
	alloc, err := a.GetAllocation(clientID)
	if err != nil {
		t.Fatalf("GetAllocation() error = %v", err)
	}

	if !alloc.VirtualIP.Equal(ip) {
		t.Errorf("Expected VirtualIP %s, got %s", ip, alloc.VirtualIP)
	}
	if alloc.ClientID != clientID {
		t.Errorf("Expected ClientID %s, got %s", clientID, alloc.ClientID)
	}
	if alloc.AllocatedAt.IsZero() {
		t.Error("AllocatedAt timestamp is zero")
	}

	// Test non-existent client
	_, err = a.GetAllocation("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent client, got nil")
	}
}

func TestAllocator_Refresh(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	clientID := "client-1"
	_, err := a.Allocate(clientID)
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}

	// Get initial allocation
	alloc1, err := a.GetAllocation(clientID)
	if err != nil {
		t.Fatalf("GetAllocation() error = %v", err)
	}

	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Refresh
	if err := a.Refresh(clientID); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// Get updated allocation
	alloc2, err := a.GetAllocation(clientID)
	if err != nil {
		t.Fatalf("GetAllocation() after refresh error = %v", err)
	}

	// Verify LastSeenAt updated
	if !alloc2.LastSeenAt.After(alloc1.LastSeenAt) {
		t.Errorf("LastSeenAt not updated: before=%v, after=%v", alloc1.LastSeenAt, alloc2.LastSeenAt)
	}

	// Test refresh on non-existent client
	err = a.Refresh("non-existent")
	if err == nil {
		t.Error("Expected error refreshing non-existent client, got nil")
	}
}

func TestAllocator_ReleaseNonExistent(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	err := a.Release("non-existent")
	if err == nil {
		t.Error("Expected error releasing non-existent client, got nil")
	}
}

func TestAllocator_EmptyClientID(t *testing.T) {
	a := newTestAllocator(t)
	defer a.Close()

	// Allocate with empty clientID
	_, err := a.Allocate("")
	if err == nil {
		t.Error("Expected error allocating with empty clientID, got nil")
	}

	// Release with empty clientID
	err = a.Release("")
	if err == nil {
		t.Error("Expected error releasing with empty clientID, got nil")
	}

	// GetAllocation with empty clientID
	_, err = a.GetAllocation("")
	if err == nil {
		t.Error("Expected error getting allocation with empty clientID, got nil")
	}

	// Refresh with empty clientID
	err = a.Refresh("")
	if err == nil {
		t.Error("Expected error refreshing with empty clientID, got nil")
	}
}

// Helper functions

func newTestAllocator(t *testing.T) Allocator {
	t.Helper()
	config := Config{
		Network: mustParseCIDR("10.100.0.0/24"),
		RelayIP: net.ParseIP("10.100.0.1"),
	}
	a, err := NewAllocator(config)
	if err != nil {
		t.Fatalf("Failed to create test allocator: %v", err)
	}
	return a
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR %s: %v", cidr, err))
	}
	return network
}
