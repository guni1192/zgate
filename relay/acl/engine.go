package acl

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/guni1192/zgate/relay/policy"
)

// Engine is the main ACL enforcement engine.
type Engine struct {
	storage       policy.PolicyStorage
	policy        *policy.Policy
	clientRules   map[string][]RuleMatcher
	mu            sync.RWMutex
	defaultAction policy.Action
}

// NewEngine creates a new ACL engine with the given storage backend.
func NewEngine(storage policy.PolicyStorage) *Engine {
	return &Engine{
		storage:       storage,
		clientRules:   make(map[string][]RuleMatcher),
		defaultAction: policy.ActionDeny,
	}
}

// LoadPolicy loads and compiles the policy from storage.
func (e *Engine) LoadPolicy(ctx context.Context) error {
	pol, err := e.storage.Load(ctx)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	clientRules := make(map[string][]RuleMatcher)
	for clientID, client := range pol.Clients {
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
	e.policy = pol
	e.clientRules = clientRules
	e.defaultAction = pol.DefaultAction
	e.mu.Unlock()

	log.Printf("[ACL] Policy loaded: %d clients, default action: %s", len(clientRules), pol.DefaultAction)
	return nil
}

// createMatcher creates a RuleMatcher based on rule type.
func (e *Engine) createMatcher(rule *policy.Rule) (RuleMatcher, error) {
	switch rule.Type {
	case policy.RuleTypeIPCIDR:
		return NewIPCIDRMatcher(rule)
	case policy.RuleTypeDefault:
		return NewDefaultMatcher(rule), nil
	// Future cases will be added here:
	// case policy.RuleTypeFQDN:
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
			Action:  policy.ActionDeny,
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
