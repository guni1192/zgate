package session

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guni1192/zgate/relay/ipam"
)

func TestManager_CreateSession(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	sess := &ClientSession{
		ClientID:    "client-1",
		SourceIP:    "192.168.1.100",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	// Create session
	ip, err := mgr.Create(sess)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if ip == nil {
		t.Fatal("Create() returned nil IP")
	}

	if sess.VirtualIP == "" {
		t.Error("Session VirtualIP not set")
	}

	if sess.VirtualIP != ip.String() {
		t.Errorf("Session VirtualIP %s != returned IP %s", sess.VirtualIP, ip.String())
	}

	// Verify session count
	if mgr.Count() != 1 {
		t.Errorf("Expected 1 session, got %d", mgr.Count())
	}
}

func TestManager_DualIndexLookup(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	sess := &ClientSession{
		ClientID:    "client-1",
		SourceIP:    "192.168.1.100",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	ip, err := mgr.Create(sess)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Lookup by Virtual IP (for packet routing)
	sessIP, ok := mgr.GetByVirtualIP(ip.String())
	if !ok {
		t.Fatal("GetByVirtualIP() not found")
	}
	if sessIP.ClientID != "client-1" {
		t.Errorf("Expected ClientID client-1, got %s", sessIP.ClientID)
	}

	// Lookup by Client ID (for admin operations)
	sessID, ok := mgr.GetByClientID("client-1")
	if !ok {
		t.Fatal("GetByClientID() not found")
	}
	if sessID.VirtualIP != ip.String() {
		t.Errorf("Expected VirtualIP %s, got %s", ip.String(), sessID.VirtualIP)
	}

	// Both lookups should return the same session object
	if sessIP != sessID {
		t.Error("GetByVirtualIP and GetByClientID returned different session objects")
	}
}

func TestManager_DeleteSession(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	sess := &ClientSession{
		ClientID:    "client-1",
		SourceIP:    "192.168.1.100",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	ip, err := mgr.Create(sess)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete session
	if err := mgr.Delete(sess); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify session removed from both indexes
	if _, ok := mgr.GetByVirtualIP(ip.String()); ok {
		t.Error("Session still found by Virtual IP after delete")
	}

	if _, ok := mgr.GetByClientID("client-1"); ok {
		t.Error("Session still found by Client ID after delete")
	}

	// Verify count updated
	if mgr.Count() != 0 {
		t.Errorf("Expected 0 sessions after delete, got %d", mgr.Count())
	}
}

func TestManager_IPReuseAfterDelete(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	// Create first session
	sess1 := &ClientSession{
		ClientID:    "client-1",
		SourceIP:    "192.168.1.100",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	ip1, err := mgr.Create(sess1)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete session
	if err := mgr.Delete(sess1); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Create second session
	sess2 := &ClientSession{
		ClientID:    "client-2",
		SourceIP:    "192.168.1.101",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	ip2, err := mgr.Create(sess2)
	if err != nil {
		t.Fatalf("Create() second session error = %v", err)
	}

	// IP should be reused
	if !ip1.Equal(ip2) {
		t.Errorf("Expected IP reuse: first=%s, second=%s", ip1, ip2)
	}
}

func TestManager_ConcurrentSessions(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	numClients := 50
	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	// Create sessions concurrently
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientNum int) {
			defer wg.Done()

			sess := &ClientSession{
				ClientID:    fmt.Sprintf("client-%d", clientNum),
				SourceIP:    fmt.Sprintf("192.168.1.%d", clientNum),
				Downstream:  &io.PipeWriter{},
				ConnectedAt: time.Now(),
			}

			_, err := mgr.Create(sess)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent create error: %v", err)
	}

	// Verify all sessions created
	if mgr.Count() != numClients {
		t.Errorf("Expected %d sessions, got %d", numClients, mgr.Count())
	}
}

func TestManager_DuplicateClientID(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	sess1 := &ClientSession{
		ClientID:    "client-1",
		SourceIP:    "192.168.1.100",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	_, err := mgr.Create(sess1)
	if err != nil {
		t.Fatalf("First Create() error = %v", err)
	}

	// Try to create another session with same ClientID
	sess2 := &ClientSession{
		ClientID:    "client-1",
		SourceIP:    "192.168.1.101",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	_, err = mgr.Create(sess2)
	if err == nil {
		t.Error("Expected error creating duplicate ClientID, got nil")
	}

	// Verify only one session exists
	if mgr.Count() != 1 {
		t.Errorf("Expected 1 session, got %d", mgr.Count())
	}
}

func TestManager_GetAllSessions(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	// Create multiple sessions
	for i := 0; i < 5; i++ {
		sess := &ClientSession{
			ClientID:    fmt.Sprintf("client-%d", i),
			SourceIP:    fmt.Sprintf("192.168.1.%d", i),
			Downstream:  &io.PipeWriter{},
			ConnectedAt: time.Now(),
		}

		_, err := mgr.Create(sess)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Get all sessions
	sessions := mgr.GetAllSessions()
	if len(sessions) != 5 {
		t.Errorf("Expected 5 sessions, got %d", len(sessions))
	}

	// Verify unique client IDs
	clientIDs := make(map[string]bool)
	for _, sess := range sessions {
		if clientIDs[sess.ClientID] {
			t.Errorf("Duplicate ClientID in GetAllSessions: %s", sess.ClientID)
		}
		clientIDs[sess.ClientID] = true
	}
}

func TestManager_NilSession(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	// Create with nil session
	_, err := mgr.Create(nil)
	if err == nil {
		t.Error("Expected error creating nil session, got nil")
	}

	// Delete with nil session
	err = mgr.Delete(nil)
	if err == nil {
		t.Error("Expected error deleting nil session, got nil")
	}
}

func TestManager_EmptyClientID(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	sess := &ClientSession{
		ClientID:    "",
		SourceIP:    "192.168.1.100",
		Downstream:  &io.PipeWriter{},
		ConnectedAt: time.Now(),
	}

	_, err := mgr.Create(sess)
	if err == nil {
		t.Error("Expected error creating session with empty ClientID, got nil")
	}
}

func TestManager_NonExistentLookup(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	// Lookup non-existent Virtual IP
	_, ok := mgr.GetByVirtualIP("10.100.0.99")
	if ok {
		t.Error("Expected false for non-existent Virtual IP lookup")
	}

	// Lookup non-existent Client ID
	_, ok = mgr.GetByClientID("non-existent")
	if ok {
		t.Error("Expected false for non-existent Client ID lookup")
	}
}

func TestManager_DeleteNonExistentSession(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.Close()

	sess := &ClientSession{
		ClientID:   "non-existent",
		VirtualIP:  "10.100.0.99",
		SourceIP:   "192.168.1.100",
		Downstream: &io.PipeWriter{},
	}

	// Should return error when trying to release non-existent IP
	err := mgr.Delete(sess)
	if err == nil {
		t.Error("Expected error deleting non-existent session, got nil")
	}
}

// Helper functions

func newTestManager(t *testing.T) *Manager {
	t.Helper()

	config := ipam.Config{
		Network: mustParseCIDR("10.100.0.0/24"),
		RelayIP: net.ParseIP("10.100.0.1"),
	}

	allocator, err := ipam.NewAllocator(config)
	if err != nil {
		t.Fatalf("Failed to create test allocator: %v", err)
	}

	return NewManager(allocator)
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR %s: %v", cidr, err))
	}
	return network
}
