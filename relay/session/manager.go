package session

import (
	"fmt"
	"net"
	"sync"

	"github.com/guni1192/zgate/relay/ipam"
)

// Manager manages client sessions with dual-index lookup.
type Manager struct {
	byVirtualIP sync.Map // string (IP) → *ClientSession (for packet routing)
	byClientID  sync.Map // string (ClientID) → *ClientSession (for admin operations)
	allocator   ipam.Allocator
	mu          sync.Mutex
}

// NewManager creates a new session manager.
func NewManager(allocator ipam.Allocator) *Manager {
	return &Manager{
		allocator: allocator,
	}
}

// Create creates a new session and allocates a Virtual IP.
// Returns the allocated Virtual IP.
func (m *Manager) Create(sess *ClientSession) (net.IP, error) {
	if sess == nil {
		return nil, fmt.Errorf("session is nil")
	}
	if sess.ClientID == "" {
		return nil, fmt.Errorf("clientID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session already exists for this client
	if existing, exists := m.byClientID.Load(sess.ClientID); exists {
		existingSess := existing.(*ClientSession)
		return net.ParseIP(existingSess.VirtualIP), fmt.Errorf("session already exists for client %s with IP %s",
			sess.ClientID, existingSess.VirtualIP)
	}

	// Allocate Virtual IP
	virtualIP, err := m.allocator.Allocate(sess.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	// Set Virtual IP on session
	sess.VirtualIP = virtualIP.String()

	// Store in both indexes
	m.byVirtualIP.Store(virtualIP.String(), sess)
	m.byClientID.Store(sess.ClientID, sess)

	return virtualIP, nil
}

// Delete removes a session and releases its Virtual IP.
func (m *Manager) Delete(sess *ClientSession) error {
	if sess == nil {
		return fmt.Errorf("session is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from both indexes
	m.byVirtualIP.Delete(sess.VirtualIP)
	m.byClientID.Delete(sess.ClientID)

	// Release IP allocation
	if err := m.allocator.Release(sess.ClientID); err != nil {
		// Log but don't fail - session is already removed from maps
		return fmt.Errorf("failed to release IP for %s: %w", sess.ClientID, err)
	}

	return nil
}

// GetByVirtualIP retrieves a session by its Virtual IP.
// Used for packet routing (destination IP lookup).
func (m *Manager) GetByVirtualIP(ip string) (*ClientSession, bool) {
	val, ok := m.byVirtualIP.Load(ip)
	if !ok {
		return nil, false
	}
	return val.(*ClientSession), true
}

// GetByClientID retrieves a session by its Client ID.
// Used for admin operations and diagnostics.
func (m *Manager) GetByClientID(clientID string) (*ClientSession, bool) {
	val, ok := m.byClientID.Load(clientID)
	if !ok {
		return nil, false
	}
	return val.(*ClientSession), true
}

// GetAllSessions returns all active sessions.
// Returns a slice of session copies to prevent external modification.
func (m *Manager) GetAllSessions() []*ClientSession {
	sessions := []*ClientSession{}
	m.byClientID.Range(func(key, value interface{}) bool {
		sess := value.(*ClientSession)
		sessions = append(sessions, sess)
		return true
	})
	return sessions
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	count := 0
	m.byClientID.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Close releases all resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Release all IP allocations
	m.byClientID.Range(func(key, value interface{}) bool {
		sess := value.(*ClientSession)
		m.allocator.Release(sess.ClientID)
		return true
	})

	// Clear maps
	m.byVirtualIP = sync.Map{}
	m.byClientID = sync.Map{}

	// Close allocator
	return m.allocator.Close()
}
