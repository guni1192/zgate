package audit

import (
	"fmt"
	"time"
)

// EventType categorizes audit events.
type EventType string

const (
	EventACLAllow     EventType = "acl.allow"
	EventACLDeny      EventType = "acl.deny"
	EventAuthSuccess  EventType = "auth.success"
	EventAuthFail     EventType = "auth.fail"
	EventConnOpen     EventType = "connection.open"
	EventConnClose    EventType = "connection.close"
	EventPolicyReload EventType = "policy.reload"
	EventError        EventType = "error"
)

// Level represents log severity.
type Level string

const (
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

// AuditEvent represents a structured audit log entry.
type AuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	EventType EventType              `json:"event_type"`
	Level     Level                  `json:"level"`
	Message   string                 `json:"message"`
	ClientID  string                 `json:"client_id,omitempty"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	DestIP    string                 `json:"dest_ip,omitempty"`
	DestPort  uint16                 `json:"dest_port,omitempty"`
	Protocol  string                 `json:"protocol,omitempty"`
	Action    string                 `json:"action,omitempty"`
	RuleID    string                 `json:"rule_id,omitempty"`
	Reason    string                 `json:"reason,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
}

// NewACLEvent creates an audit event for ACL decisions.
func NewACLEvent(clientID string, destIP string, action string, ruleID string, reason string) *AuditEvent {
	level := LevelInfo
	eventType := EventACLAllow

	if action == "deny" {
		level = LevelWarn
		eventType = EventACLDeny
	}

	return &AuditEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Level:     level,
		Message:   fmt.Sprintf("ACL %s for client %s to %s", action, clientID, destIP),
		ClientID:  clientID,
		DestIP:    destIP,
		Action:    action,
		RuleID:    ruleID,
		Reason:    reason,
		Metadata:  make(map[string]interface{}),
	}
}

// NewAuthEvent creates an audit event for authentication.
func NewAuthEvent(clientID string, success bool, reason string) *AuditEvent {
	level := LevelInfo
	eventType := EventAuthSuccess
	message := fmt.Sprintf("Authentication successful for %s", clientID)

	if !success {
		level = LevelError
		eventType = EventAuthFail
		message = fmt.Sprintf("Authentication failed for %s: %s", clientID, reason)
	}

	return &AuditEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Level:     level,
		Message:   message,
		ClientID:  clientID,
		Reason:    reason,
		Metadata:  make(map[string]interface{}),
	}
}

// NewConnectionEvent creates an audit event for connection lifecycle.
func NewConnectionEvent(clientID string, sourceIP string, isOpen bool) *AuditEvent {
	eventType := EventConnClose
	message := fmt.Sprintf("Connection closed: %s from %s", clientID, sourceIP)

	if isOpen {
		eventType = EventConnOpen
		message = fmt.Sprintf("Connection established: %s from %s", clientID, sourceIP)
	}

	return &AuditEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		Level:     LevelInfo,
		Message:   message,
		ClientID:  clientID,
		SourceIP:  sourceIP,
		Metadata:  make(map[string]interface{}),
	}
}
