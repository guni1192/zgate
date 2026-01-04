package policy

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
