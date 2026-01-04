package policy

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
