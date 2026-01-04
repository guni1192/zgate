package policy

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

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyInvalid, err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyInvalid, err)
	}

	s.cached = &p
	return &p, nil
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
