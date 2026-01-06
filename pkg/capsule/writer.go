package capsule

import (
	"fmt"
	"io"
	"sync"
)

// CapsuleWriter writes capsules to a stream.
// Thread-safe for concurrent writes.
type CapsuleWriter struct {
	w  io.Writer
	mu sync.Mutex
}

// NewCapsuleWriter creates a new CapsuleWriter.
func NewCapsuleWriter(w io.Writer) *CapsuleWriter {
	return &CapsuleWriter{w: w}
}

// WriteCapsule writes a capsule to the stream.
// Thread-safe: multiple goroutines can call this concurrently.
func (cw *CapsuleWriter) WriteCapsule(cap *Capsule) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	encoded, err := EncodeCapsule(cap)
	if err != nil {
		return fmt.Errorf("encode capsule: %w", err)
	}

	if _, err := cw.w.Write(encoded); err != nil {
		return fmt.Errorf("write capsule: %w", err)
	}

	return nil
}
