package session

import (
	"io"
	"sync"
	"time"
)

// ClientSession represents an active client connection.
type ClientSession struct {
	ClientID      string
	VirtualIP     string
	SourceIP      string
	Downstream    *io.PipeWriter
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
	mu            sync.Mutex
}

// UpdateActivity updates the last activity timestamp.
func (s *ClientSession) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// AddBytesSent increments the sent byte counter.
func (s *ClientSession) AddBytesSent(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BytesSent += n
}

// AddBytesReceived increments the received byte counter.
func (s *ClientSession) AddBytesReceived(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BytesReceived += n
}

// GetStats returns session statistics.
func (s *ClientSession) GetStats() SessionStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	return SessionStats{
		ClientID:      s.ClientID,
		VirtualIP:     s.VirtualIP,
		ConnectedAt:   s.ConnectedAt,
		Duration:      time.Since(s.ConnectedAt),
		BytesSent:     s.BytesSent,
		BytesReceived: s.BytesReceived,
	}
}

// SessionStats is an immutable snapshot of session statistics.
type SessionStats struct {
	ClientID      string
	VirtualIP     string
	ConnectedAt   time.Time
	Duration      time.Duration
	BytesSent     uint64
	BytesReceived uint64
}
