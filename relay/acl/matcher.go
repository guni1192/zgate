package acl

import (
	"fmt"
	"net"

	"github.com/guni1192/zgate/relay/policy"
)

// PacketInfo contains extracted packet information for ACL matching.
type PacketInfo struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol uint8  // TCP=6, UDP=17, ICMP=1
	SrcPort  uint16
	DstPort  uint16
	FQDN     string // Future: DNS query FQDN (Phase 3.3+)
}

// MatchResult contains the result of an ACL rule match.
type MatchResult struct {
	Matched  bool
	Action   policy.Action
	RuleID   string
	Reason   string
	Metadata map[string]string
}

// RuleMatcher is the interface for different rule types.
type RuleMatcher interface {
	Match(packet *PacketInfo) (*MatchResult, error)
	Type() policy.RuleType
	String() string
}

// IPCIDRMatcher matches packets based on destination IP CIDR ranges.
type IPCIDRMatcher struct {
	rule     *policy.Rule
	cidrs    []*net.IPNet
	ruleID   string
	action   policy.Action
	metadata map[string]string
}

// NewIPCIDRMatcher creates a matcher for IP CIDR rules.
func NewIPCIDRMatcher(rule *policy.Rule) (*IPCIDRMatcher, error) {
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

func (m *IPCIDRMatcher) Type() policy.RuleType {
	return policy.RuleTypeIPCIDR
}

func (m *IPCIDRMatcher) String() string {
	return fmt.Sprintf("IPCIDRMatcher[%s: %v]", m.action, m.cidrs)
}

// DefaultMatcher always matches (catch-all rule).
type DefaultMatcher struct {
	rule   *policy.Rule
	action policy.Action
}

func NewDefaultMatcher(rule *policy.Rule) *DefaultMatcher {
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

func (m *DefaultMatcher) Type() policy.RuleType {
	return policy.RuleTypeDefault
}

func (m *DefaultMatcher) String() string {
	return fmt.Sprintf("DefaultMatcher[%s]", m.action)
}
