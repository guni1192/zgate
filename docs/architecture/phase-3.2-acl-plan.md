# Phase 3.2 Implementation Plan: Extensible ACL Architecture

## Overview

Implement a **production-ready, extensible ACL system** for Phase 3.2 with future-proofing for:
- **Phase 3.3+**: FQDN-based ACL (e.g., "*.google.com")
- **Phase 4+**: API-based Policy CRUD (runtime policy updates)
- **All Phases**: Unified audit logging across all components

**Phase 3.2 Implementation Scope:**
- ✅ IP-based ACL with CIDR notation
- ✅ Static YAML policy file
- ✅ Structured audit logging (JSON/Text formatters)
- ✅ Modular package structure for extensibility
- ❌ FQDN matching (design interfaces only)
- ❌ API-based policy CRUD (design interfaces only)

---

## Architecture Design

### Package Structure

```
masque-relay/
├── main.go                         # HTTP/3 server, integration glue
├── acl/                            # ACL enforcement engine
│   ├── policy.go                   # Policy data structures (extensible)
│   ├── types.go                    # Enums (RuleType, Action)
│   ├── engine.go                   # ACL enforcement engine
│   ├── matcher.go                  # Matcher interface + IP CIDR + Default
│   ├── storage.go                  # Storage abstraction interface
│   ├── yaml_storage.go             # YAML file implementation
│   └── acl_test.go                 # Unit tests
├── audit/                          # Audit logging package
│   ├── events.go                   # Event type definitions
│   ├── logger.go                   # Structured audit logger
│   ├── formatter.go                # JSON/Text formatters
│   └── audit_test.go               # Unit tests
├── session/                        # Session management
│   └── session.go                  # ClientSession struct
└── internal/                       # Internal utilities (optional)
```

**Design Principles:**
- **Separation of Concerns**: Each package has single responsibility
- **Interface Segregation**: Small, focused interfaces
- **Open/Closed**: Open for extension, closed for modification
- **Dependency Inversion**: Core logic depends on interfaces, not implementations

---

## Implementation Steps

### Step 1: Create ACL Package Foundation

#### 1.1 Define Types and Constants

**File:** [masque-relay/acl/types.go](masque-relay/acl/types.go)

```go
package acl

// RuleType represents the type of ACL rule.
type RuleType string

const (
	RuleTypeIPCIDR  RuleType = "ip_cidr"  // Phase 3.2
	RuleTypeDefault RuleType = "default"  // Catch-all rule

	// Future rule types (DO NOT implement in Phase 3.2):
	// RuleTypeFQDN      RuleType = "fqdn"       // Phase 3.3
	// RuleTypeFQDNRegex RuleType = "fqdn_regex" // Phase 3.4
	// RuleTypeGeo       RuleType = "geo"        // Phase 4
)

func (rt RuleType) IsValid() bool {
	switch rt {
	case RuleTypeIPCIDR, RuleTypeDefault:
		return true
	default:
		return false
	}
}

// Action represents the ACL decision.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

func (a Action) IsValid() bool {
	return a == ActionAllow || a == ActionDeny
}
```

#### 1.2 Define Policy Data Structures

**File:** [masque-relay/acl/policy.go](masque-relay/acl/policy.go)

```go
package acl

import (
	"fmt"
	"time"
)

// Policy represents the complete ACL policy document.
type Policy struct {
	Version       string              `yaml:"version"`
	Metadata      PolicyMetadata      `yaml:"metadata,omitempty"`
	DefaultAction Action              `yaml:"default_action"`
	Clients       map[string]*Client  `yaml:"clients"`
}

// PolicyMetadata contains policy metadata.
type PolicyMetadata struct {
	Name        string    `yaml:"name,omitempty"`
	Description string    `yaml:"description,omitempty"`
	CreatedAt   time.Time `yaml:"created_at,omitempty"`
}

// Client represents a single client's ACL configuration.
type Client struct {
	Description string  `yaml:"description"`
	Rules       []*Rule `yaml:"rules"`
}

// Rule represents a single ACL rule.
type Rule struct {
	ID           string            `yaml:"id"`
	Type         RuleType          `yaml:"type"`
	Action       Action            `yaml:"action"`
	Destinations []string          `yaml:"destinations,omitempty"` // For IP/FQDN rules
	Metadata     map[string]string `yaml:"metadata,omitempty"`     // Extensible metadata

	// Future fields (commented out for Phase 3.2):
	// Priority     int               `yaml:"priority,omitempty"`
	// Enabled      bool              `yaml:"enabled,omitempty"`
	// ExpiresAt    *time.Time        `yaml:"expires_at,omitempty"`
}

// Validate checks if the policy is structurally valid.
func (p *Policy) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("version is required")
	}
	if p.Version != "1.0" {
		return fmt.Errorf("unsupported version: %s", p.Version)
	}
	if len(p.Clients) == 0 {
		return fmt.Errorf("at least one client is required")
	}
	for clientID, client := range p.Clients {
		if len(client.Rules) == 0 {
			return fmt.Errorf("client %s has no rules", clientID)
		}
		for i, rule := range client.Rules {
			if err := rule.Validate(); err != nil {
				return fmt.Errorf("client %s rule %d: %w", clientID, i, err)
			}
		}
	}
	return nil
}

// Validate checks if a rule is valid.
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if !r.Type.IsValid() {
		return fmt.Errorf("invalid rule type: %s", r.Type)
	}
	if !r.Action.IsValid() {
		return fmt.Errorf("invalid action: %s", r.Action)
	}
	if r.Type == RuleTypeIPCIDR && len(r.Destinations) == 0 {
		return fmt.Errorf("ip_cidr rule requires destinations")
	}
	return nil
}
```

#### 1.3 Define Storage Abstraction

**File:** [masque-relay/acl/storage.go](masque-relay/acl/storage.go)

```go
package acl

import (
	"context"
	"errors"
	"time"
)

// PolicyStorage abstracts the underlying policy storage mechanism.
type PolicyStorage interface {
	// Load retrieves the current policy from storage.
	Load(ctx context.Context) (*Policy, error)

	// Save persists the policy to storage (for future API-based updates).
	Save(ctx context.Context, policy *Policy) error

	// Watch returns a channel for policy change notifications.
	Watch(ctx context.Context) (<-chan PolicyUpdate, error)

	// Close releases resources.
	Close() error
}

// PolicyUpdate represents a policy change notification.
type PolicyUpdate struct {
	Timestamp time.Time
	Policy    *Policy
	Source    string // "file", "api", "database"
	ChangeID  string
}

// Errors
var (
	ErrPolicyNotFound     = errors.New("policy not found")
	ErrPolicyInvalid      = errors.New("policy validation failed")
	ErrStorageUnavailable = errors.New("storage backend unavailable")
)
```

**File:** [masque-relay/acl/yaml_storage.go](masque-relay/acl/yaml_storage.go)

```go
package acl

import (
	"context"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// YAMLFileStorage implements PolicyStorage for local YAML files.
type YAMLFileStorage struct {
	filePath string
	mu       sync.RWMutex
	cached   *Policy
}

// NewYAMLFileStorage creates a new YAML file storage backend.
func NewYAMLFileStorage(filePath string) *YAMLFileStorage {
	return &YAMLFileStorage{
		filePath: filePath,
	}
}

func (s *YAMLFileStorage) Load(ctx context.Context) (*Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, s.filePath)
		}
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyInvalid, err)
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyInvalid, err)
	}

	s.cached = &policy
	return &policy, nil
}

func (s *YAMLFileStorage) Save(ctx context.Context, policy *Policy) error {
	return fmt.Errorf("YAML storage is read-only in Phase 3.2")
}

func (s *YAMLFileStorage) Watch(ctx context.Context) (<-chan PolicyUpdate, error) {
	// Phase 3.2: No hot-reload support
	ch := make(chan PolicyUpdate)
	close(ch)
	return ch, nil
}

func (s *YAMLFileStorage) Close() error {
	return nil
}
```

#### 1.4 Define Matcher Interface

**File:** [masque-relay/acl/matcher.go](masque-relay/acl/matcher.go)

```go
package acl

import (
	"fmt"
	"net"
)

// PacketInfo contains extracted packet information for ACL matching.
type PacketInfo struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol uint8    // TCP=6, UDP=17, ICMP=1
	SrcPort  uint16
	DstPort  uint16
	FQDN     string   // Future: DNS query FQDN (Phase 3.3+)
}

// MatchResult contains the result of an ACL rule match.
type MatchResult struct {
	Matched  bool
	Action   Action
	RuleID   string
	Reason   string
	Metadata map[string]string
}

// RuleMatcher is the interface for different rule types.
type RuleMatcher interface {
	Match(packet *PacketInfo) (*MatchResult, error)
	Type() RuleType
	String() string
}

// IPCIDRMatcher matches packets based on destination IP CIDR ranges.
type IPCIDRMatcher struct {
	rule     *Rule
	cidrs    []*net.IPNet
	ruleID   string
	action   Action
	metadata map[string]string
}

// NewIPCIDRMatcher creates a matcher for IP CIDR rules.
func NewIPCIDRMatcher(rule *Rule) (*IPCIDRMatcher, error) {
	var cidrs []*net.IPNet
	for _, dest := range rule.Destinations {
		_, ipnet, err := net.ParseCIDR(dest)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", dest, err)
		}
		cidrs = append(cidrs, ipnet)
	}

	return &IPCIDRMatcher{
		rule:     rule,
		cidrs:    cidrs,
		ruleID:   rule.ID,
		action:   rule.Action,
		metadata: rule.Metadata,
	}, nil
}

func (m *IPCIDRMatcher) Match(packet *PacketInfo) (*MatchResult, error) {
	for _, cidr := range m.cidrs {
		if cidr.Contains(packet.DstIP) {
			return &MatchResult{
				Matched:  true,
				Action:   m.action,
				RuleID:   m.ruleID,
				Reason:   fmt.Sprintf("Matched CIDR %s", cidr.String()),
				Metadata: m.metadata,
			}, nil
		}
	}
	return &MatchResult{Matched: false}, nil
}

func (m *IPCIDRMatcher) Type() RuleType {
	return RuleTypeIPCIDR
}

func (m *IPCIDRMatcher) String() string {
	return fmt.Sprintf("IPCIDRMatcher[%s: %v]", m.action, m.cidrs)
}

// DefaultMatcher always matches (catch-all rule).
type DefaultMatcher struct {
	rule   *Rule
	action Action
}

func NewDefaultMatcher(rule *Rule) *DefaultMatcher {
	return &DefaultMatcher{
		rule:   rule,
		action: rule.Action,
	}
}

func (m *DefaultMatcher) Match(packet *PacketInfo) (*MatchResult, error) {
	return &MatchResult{
		Matched: true,
		Action:  m.action,
		RuleID:  m.rule.ID,
		Reason:  "Default rule (catch-all)",
	}, nil
}

func (m *DefaultMatcher) Type() RuleType {
	return RuleTypeDefault
}

func (m *DefaultMatcher) String() string {
	return fmt.Sprintf("DefaultMatcher[%s]", m.action)
}
```

#### 1.5 Implement ACL Engine

**File:** [masque-relay/acl/engine.go](masque-relay/acl/engine.go)

```go
package acl

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// Engine is the main ACL enforcement engine.
type Engine struct {
	storage       PolicyStorage
	policy        *Policy
	clientRules   map[string][]RuleMatcher
	mu            sync.RWMutex
	defaultAction Action
}

// NewEngine creates a new ACL engine with the given storage backend.
func NewEngine(storage PolicyStorage) *Engine {
	return &Engine{
		storage:       storage,
		clientRules:   make(map[string][]RuleMatcher),
		defaultAction: ActionDeny,
	}
}

// LoadPolicy loads and compiles the policy from storage.
func (e *Engine) LoadPolicy(ctx context.Context) error {
	policy, err := e.storage.Load(ctx)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	clientRules := make(map[string][]RuleMatcher)
	for clientID, client := range policy.Clients {
		var matchers []RuleMatcher
		for i, rule := range client.Rules {
			matcher, err := e.createMatcher(rule)
			if err != nil {
				log.Printf("[ACL] Warning: skipping rule %d for client %s: %v", i, clientID, err)
				continue
			}
			matchers = append(matchers, matcher)
		}
		clientRules[clientID] = matchers
	}

	e.mu.Lock()
	e.policy = policy
	e.clientRules = clientRules
	e.defaultAction = policy.DefaultAction
	e.mu.Unlock()

	log.Printf("[ACL] Policy loaded: %d clients, default action: %s", len(clientRules), policy.DefaultAction)
	return nil
}

// createMatcher creates a RuleMatcher based on rule type.
func (e *Engine) createMatcher(rule *Rule) (RuleMatcher, error) {
	switch rule.Type {
	case RuleTypeIPCIDR:
		return NewIPCIDRMatcher(rule)
	case RuleTypeDefault:
		return NewDefaultMatcher(rule), nil
	// Future cases will be added here:
	// case RuleTypeFQDN:
	//     return NewFQDNMatcher(rule)
	default:
		return nil, fmt.Errorf("unsupported rule type: %s", rule.Type)
	}
}

// CheckAccess evaluates ACL rules for a packet from a specific client.
func (e *Engine) CheckAccess(clientID string, packet *PacketInfo) (*MatchResult, error) {
	e.mu.RLock()
	matchers, exists := e.clientRules[clientID]
	e.mu.RUnlock()

	if !exists {
		return &MatchResult{
			Matched: true,
			Action:  ActionDeny,
			Reason:  fmt.Sprintf("Unknown client: %s", clientID),
		}, nil
	}

	// Evaluate rules in order (first match wins)
	for _, matcher := range matchers {
		result, err := matcher.Match(packet)
		if err != nil {
			log.Printf("[ACL] Match error for client %s: %v", clientID, err)
			continue
		}
		if result.Matched {
			return result, nil
		}
	}

	// No rule matched - apply default action
	return &MatchResult{
		Matched: true,
		Action:  e.defaultAction,
		Reason:  "No matching rule, applied default action",
	}, nil
}

// Reload reloads the policy from storage.
func (e *Engine) Reload(ctx context.Context) error {
	return e.LoadPolicy(ctx)
}

// Close releases resources.
func (e *Engine) Close() error {
	return e.storage.Close()
}
```

---

### Step 2: Create Audit Logging Package

#### 2.1 Define Event Types

**File:** [masque-relay/audit/events.go](masque-relay/audit/events.go)

```go
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
```

#### 2.2 Implement Logger

**File:** [masque-relay/audit/logger.go](masque-relay/audit/logger.go)

```go
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
```

#### 2.3 Implement Formatters

**File:** [masque-relay/audit/formatter.go](masque-relay/audit/formatter.go)

```go
package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

// Formatter formats audit events for output.
type Formatter interface {
	Format(event *AuditEvent) ([]byte, error)
}

// JSONFormatter formats events as JSON (production default).
type JSONFormatter struct {
	Pretty bool
}

func (f *JSONFormatter) Format(event *AuditEvent) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(event, "", "  ")
	}
	return json.Marshal(event)
}

// TextFormatter formats events as human-readable text.
type TextFormatter struct {
	TimeFormat string
}

func (f *TextFormatter) Format(event *AuditEvent) ([]byte, error) {
	timeFormat := f.TimeFormat
	if timeFormat == "" {
		timeFormat = time.RFC3339
	}

	output := fmt.Sprintf("[%s] [%s] [%s] %s",
		event.Timestamp.Format(timeFormat),
		event.Level,
		event.EventType,
		event.Message,
	)

	if event.ClientID != "" {
		output += fmt.Sprintf(" client_id=%s", event.ClientID)
	}
	if event.DestIP != "" {
		output += fmt.Sprintf(" dest_ip=%s", event.DestIP)
	}
	if event.Action != "" {
		output += fmt.Sprintf(" action=%s", event.Action)
	}
	if event.RuleID != "" {
		output += fmt.Sprintf(" rule_id=%s", event.RuleID)
	}
	if event.Reason != "" {
		output += fmt.Sprintf(" reason=%q", event.Reason)
	}

	return []byte(output), nil
}
```

---

### Step 3: Create Session Package

**File:** [masque-relay/session/session.go](masque-relay/session/session.go)

```go
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
```

---

### Step 4: Create Policy Configuration

**File:** [policy.yaml](policy.yaml)

```yaml
version: "1.0"
metadata:
  name: "masque-ztna-policy"
  description: "IP-based ACL for medical institutions"
  created_at: "2026-01-03T00:00:00Z"

default_action: deny

clients:
  client-1:
    description: "Medical Institution A - Restricted Access"
    rules:
      - id: "allow-dns"
        type: ip_cidr
        action: allow
        destinations:
          - 8.8.8.8/32
          - 1.1.1.1/32
        metadata:
          reason: "DNS resolution"
          category: "infrastructure"

      - id: "deny-default"
        type: default
        action: deny

  client-2:
    description: "Medical Institution B - Full Internet Access"
    rules:
      - id: "allow-all"
        type: ip_cidr
        action: allow
        destinations:
          - 0.0.0.0/0
        metadata:
          reason: "Full internet access"
          category: "unrestricted"
```

---

### Step 5: Integrate into main.go

**File:** [masque-relay/main.go](masque-relay/main.go)

**Changes required:**

1. **Import new packages** (top of file):
```go
import (
	// ... existing imports ...
	"masque-relay/acl"
	"masque-relay/audit"
	"masque-relay/session"
)
```

2. **Add global variables** (after line 33):
```go
var (
	sessionMap  sync.Map
	aclEngine   *acl.Engine
	auditLogger *audit.Logger
)
```

3. **Initialize in main()** (after line 47):
```go
// Initialize audit logger
auditLogger = audit.NewLogger(
	&audit.JSONFormatter{},
	os.Stdout,
)
defer auditLogger.Close()

// Initialize ACL engine
policyPath := os.Getenv("ACL_POLICY_PATH")
if policyPath == "" {
	policyPath = "/etc/masque/policy.yaml"
}

storage := acl.NewYAMLFileStorage(policyPath)
aclEngine = acl.NewEngine(storage)

if err := aclEngine.LoadPolicy(context.Background()); err != nil {
	log.Fatalf("Failed to load ACL policy: %v", err)
}
defer aclEngine.Close()
```

4. **Update handleMasqueRequest** (lines 85-176):

```go
func handleMasqueRequest(w http.ResponseWriter, r *http.Request, tun *water.Interface) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientID := extractClientID(r)
	clientVirtualIP := "10.100.0.2"
	sourceIP := r.RemoteAddr

	auditLogger.LogConnection(clientID, sourceIP, true)
	log.Printf("Client connected: %s (CN: %s), Virtual IP: %s", sourceIP, clientID, clientVirtualIP)

	pr, pw := io.Pipe()

	sess := &session.ClientSession{
		ClientID:    clientID,
		VirtualIP:   clientVirtualIP,
		SourceIP:    sourceIP,
		Downstream:  pw,
		ConnectedAt: time.Now(),
	}

	sessionMap.Store(clientVirtualIP, sess)
	defer func() {
		sessionMap.Delete(clientVirtualIP)
		pw.Close()
		auditLogger.LogConnection(clientID, sourceIP, false)
		log.Printf("Client disconnected: %s (CN: %s)", clientVirtualIP, clientID)
	}()

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	errChan := make(chan error, 2)

	// Upstream: Request Body -> TUN (with ACL check)
	go func() {
		lenBuf := make([]byte, 2)
		packetBuf := make([]byte, 2000)
		for {
			if _, err := io.ReadFull(r.Body, lenBuf); err != nil {
				errChan <- err
				return
			}
			plen := binary.BigEndian.Uint16(lenBuf)
			if _, err := io.ReadFull(r.Body, packetBuf[:plen]); err != nil {
				errChan <- err
				return
			}

			// Extract packet info for ACL check
			packetInfo := extractPacketInfo(packetBuf[:plen])

			// ACL Check
			result, err := aclEngine.CheckAccess(clientID, packetInfo)
			if err != nil {
				log.Printf("[ACL] Error: %v", err)
				continue
			}

			// Log ACL decision
			auditLogger.LogACL(clientID, packetInfo.DstIP.String(),
				string(result.Action), result.RuleID, result.Reason)

			if result.Action == acl.ActionDeny {
				continue // Drop packet
			}

			// Allow: Write to TUN
			sess.AddBytesReceived(uint64(plen))
			_, err = tun.Write(packetBuf[:plen])
			if err != nil {
				log.Printf("TUN Write Error: %v", err)
			}
		}
	}()

	// Downstream: Pipe -> Response Body (unchanged)
	go func() {
		buf := make([]byte, 2000)
		for {
			n, err := pr.Read(buf)
			if err != nil {
				errChan <- err
				return
			}

			binary.Write(w, binary.BigEndian, uint16(n))
			_, err = w.Write(buf[:n])
			if err != nil {
				errChan <- err
				return
			}

			sess.AddBytesSent(uint64(n))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}()

	<-errChan
}

// extractPacketInfo parses packet data to extract ACL-relevant information.
func extractPacketInfo(data []byte) *acl.PacketInfo {
	info := &acl.PacketInfo{}

	if len(data) < 20 {
		return info
	}

	version := data[0] >> 4
	if version != 4 {
		return info
	}

	info.Protocol = data[9]
	info.SrcIP = net.IP(data[12:16])
	info.DstIP = net.IP(data[16:20])

	headerLen := int(data[0]&0x0F) * 4
	if info.Protocol == 6 || info.Protocol == 17 {
		if len(data) >= headerLen+4 {
			info.SrcPort = binary.BigEndian.Uint16(data[headerLen : headerLen+2])
			info.DstPort = binary.BigEndian.Uint16(data[headerLen+2 : headerLen+4])
		}
	}

	return info
}
```

5. **Update handleTunRead** (lines 178-221):
```go
// Update session map access to use session.ClientSession
if val, ok := sessionMap.Load(dstIP.String()); ok {
	sess := val.(*session.ClientSession)
	sess.Downstream.Write(raw)
	log.Printf("[Relay] Routing packet to %s (%d bytes)", dstIP, n)
}
```

---

### Step 6: Update Docker Configuration

**File:** [compose.yaml](compose.yaml)

1. **Add policy mount to relay** (line 11-12):
```yaml
volumes:
  - ./certs:/certs:ro
  - ./policy.yaml:/etc/masque/policy.yaml:ro
```

2. **Add environment variable** (line 13-15):
```yaml
environment:
  - USE_MTLS=${USE_MTLS:-true}
  - ACL_POLICY_PATH=/etc/masque/policy.yaml
```

3. **Add client-2 service** (after line 39):
```yaml
client-2:
  build: ./masque-client
  container_name: masque-client-2
  depends_on:
    - relay
  cap_add:
    - NET_ADMIN
  devices:
    - /dev/net/tun:/dev/net/tun
  volumes:
    - ./certs:/certs:ro
  environment:
    - RELAY_URL=https://172.28.0.10:4433/
    - CLIENT_ID=client-2
    - USE_MTLS=${USE_MTLS:-true}
    - TARGET_CIDRS=0.0.0.0/0
  networks:
    masque-net:
      ipv4_address: 172.28.0.21
```

---

### Step 7: Create Integration Test

**File:** [test-acl.sh](test-acl.sh)

```bash
#!/bin/bash
set -e

echo "=== Phase 3.2 ACL E2E Test Suite ==="

echo "Starting environment..."
docker compose down -v
docker compose up --build -d

echo "Waiting for tunnel stabilization..."
sleep 5

echo ""
echo "Test 1: client-1 can ping 8.8.8.8 (ALLOWED by policy)"
if docker compose exec client ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1; then
    echo "✓ PASS: client-1 -> 8.8.8.8 allowed"
else
    echo "✗ FAIL: client-1 -> 8.8.8.8 denied (should be allowed)"
    exit 1
fi

echo ""
echo "Test 2: client-1 CANNOT ping 1.0.0.1 (DENIED by policy)"
if docker compose exec client ping -c 2 -W 3 1.0.0.1 > /dev/null 2>&1; then
    echo "✗ FAIL: client-1 -> 1.0.0.1 allowed (should be denied)"
    exit 1
else
    echo "✓ PASS: client-1 -> 1.0.0.1 denied"
fi

echo ""
echo "Test 3: client-2 can ping 8.8.8.8 (ALLOWED by wildcard)"
if docker compose exec client-2 ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1; then
    echo "✓ PASS: client-2 -> 8.8.8.8 allowed"
else
    echo "✗ FAIL: client-2 -> 8.8.8.8 denied (should be allowed)"
    exit 1
fi

echo ""
echo "Test 4: client-2 can ping 1.0.0.1 (ALLOWED by wildcard)"
if docker compose exec client-2 ping -c 2 -W 3 1.0.0.1 > /dev/null 2>&1; then
    echo "✓ PASS: client-2 -> 1.0.0.1 allowed"
else
    echo "✗ FAIL: client-2 -> 1.0.0.1 denied (should be allowed)"
    exit 1
fi

echo ""
echo "=== Checking Audit Logs ==="
echo "ACL DENY logs (should see client-1 denied to 1.0.0.1):"
docker compose logs relay | grep "acl.deny" | tail -10

echo ""
echo "ACL ALLOW logs (sample):"
docker compose logs relay | grep "acl.allow" | head -5

echo ""
echo "✓ All ACL tests passed!"
```

**Make executable:**
```bash
chmod +x test-acl.sh
```

---

### Step 8: Update Build Dependencies

**File:** [masque-relay/go.mod](masque-relay/go.mod)

Run:
```bash
cd masque-relay
go get gopkg.in/yaml.v3
go mod tidy
```

---

## Migration Path to Phase 3.3 (FQDN Support)

### Step 1: Update Policy Schema (Backward Compatible)

```yaml
version: "1.0"  # Still works!
clients:
  client-1:
    rules:
      # Existing IP rules (unchanged)
      - id: "allow-dns"
        type: ip_cidr
        action: allow
        destinations: ["8.8.8.8/32"]

      # NEW: FQDN rule
      - id: "allow-google"
        type: fqdn
        action: allow
        destinations: ["*.google.com"]
```

### Step 2: Implement FQDNMatcher

Create [masque-relay/acl/matcher_fqdn.go](masque-relay/acl/matcher_fqdn.go) (Phase 3.3)

### Step 3: Enable RuleTypeFQDN in types.go

Uncomment `RuleTypeFQDN` in `IsValid()` function

### Step 4: Update Engine

Add case for `RuleTypeFQDN` in `createMatcher()`

**No changes needed to:**
- Storage interface ✓
- Audit logger ✓
- Policy validation ✓
- Main integration ✓

---

## Files Summary

### Files to Create (Phase 3.2):

**ACL Package (7 files):**
1. `masque-relay/acl/types.go` - Enums and constants
2. `masque-relay/acl/policy.go` - Policy data structures
3. `masque-relay/acl/storage.go` - Storage interface
4. `masque-relay/acl/yaml_storage.go` - YAML implementation
5. `masque-relay/acl/matcher.go` - Matchers (IP CIDR + Default)
6. `masque-relay/acl/engine.go` - ACL enforcement engine
7. `masque-relay/acl/acl_test.go` - Unit tests

**Audit Package (4 files):**
8. `masque-relay/audit/events.go` - Event types
9. `masque-relay/audit/logger.go` - Logger implementation
10. `masque-relay/audit/formatter.go` - JSON/Text formatters
11. `masque-relay/audit/audit_test.go` - Unit tests

**Session Package (1 file):**
12. `masque-relay/session/session.go` - ClientSession struct

**Configuration (2 files):**
13. `policy.yaml` - ACL policy configuration
14. `test-acl.sh` - Integration test script

### Files to Modify (Phase 3.2):

1. `masque-relay/main.go` - Add ACL/audit integration
2. `masque-relay/go.mod` - Add gopkg.in/yaml.v3
3. `compose.yaml` - Mount policy, add client-2
4. `Makefile` - Add test-acl target

### Files to Stub (DO NOT implement in Phase 3.2):

- `masque-relay/acl/matcher_fqdn.go` - Phase 3.3
- `masque-relay/acl/matcher_geo.go` - Phase 4
- `masque-relay/acl/database_storage.go` - Phase 4
- `masque-relay/acl/api_storage.go` - Phase 4

---

## Testing Checklist

### Unit Tests:
- [ ] Run `cd masque-relay && go test ./acl/...`
- [ ] Run `cd masque-relay && go test ./audit/...`
- [ ] All policy parsing tests pass
- [ ] All CIDR matching tests pass
- [ ] Invalid policy handling works

### Integration Tests:
- [ ] Run `docker compose up --build`
- [ ] Both clients start successfully
- [ ] Run `./test-acl.sh`
- [ ] client-1: 8.8.8.8 succeeds, 1.0.0.1 fails
- [ ] client-2: Both destinations succeed
- [ ] Audit logs show correct events
- [ ] Run `make test-all`

---

## Success Criteria

Phase 3.2 is complete when:

1. ✅ Modular package structure (acl/, audit/, session/)
2. ✅ ACL policy loads from YAML at startup
3. ✅ IP CIDR matching works correctly
4. ✅ Client-1 restricted, Client-2 unrestricted
5. ✅ Structured audit logs (JSON format)
6. ✅ All unit tests pass
7. ✅ Integration tests pass
8. ✅ Architecture supports future FQDN/API extensions
9. ✅ No performance degradation (<5% overhead)
10. ✅ Documentation updated

---

## Implementation Order

**Day 1: Core ACL Logic**
1. Create acl/ package structure
2. Implement all ACL files
3. Write unit tests
4. Verify `go test ./acl/...` passes

**Day 2: Audit + Session**
1. Create audit/ package
2. Create session/ package
3. Write unit tests
4. Create policy.yaml

**Day 3: Integration**
1. Update main.go with ACL/audit integration
2. Update compose.yaml
3. Add extractPacketInfo() helper
4. Test with `docker compose up --build`

**Day 4: Testing**
1. Create test-acl.sh
2. Update Makefile
3. Run full test suite
4. Update CLAUDE.md documentation
