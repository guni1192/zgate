package policy

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
