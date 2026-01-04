package audit

import (
	"io"
	"log"
	"os"
	"sync"
)

// Logger is a structured audit logger.
type Logger struct {
	formatter Formatter
	output    io.Writer
	mu        sync.Mutex
}

// NewLogger creates a new audit logger.
func NewLogger(formatter Formatter, output io.Writer) *Logger {
	if output == nil {
		output = os.Stderr
	}
	return &Logger{
		formatter: formatter,
		output:    output,
	}
}

// Log writes an audit event to the output.
func (l *Logger) Log(event *AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := l.formatter.Format(event)
	if err != nil {
		return err
	}

	_, err = l.output.Write(append(data, '\n'))
	return err
}

// LogACL is a convenience method for ACL events.
func (l *Logger) LogACL(clientID string, destIP string, action string, ruleID string, reason string) {
	event := NewACLEvent(clientID, destIP, action, ruleID, reason)
	if err := l.Log(event); err != nil {
		log.Printf("[Audit] Failed to log event: %v", err)
	}
}

// LogAuth is a convenience method for authentication events.
func (l *Logger) LogAuth(clientID string, success bool, reason string) {
	event := NewAuthEvent(clientID, success, reason)
	if err := l.Log(event); err != nil {
		log.Printf("[Audit] Failed to log event: %v", err)
	}
}

// LogConnection is a convenience method for connection events.
func (l *Logger) LogConnection(clientID string, sourceIP string, isOpen bool) {
	event := NewConnectionEvent(clientID, sourceIP, isOpen)
	if err := l.Log(event); err != nil {
		log.Printf("[Audit] Failed to log event: %v", err)
	}
}

// Close closes the logger.
func (l *Logger) Close() error {
	if closer, ok := l.output.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
