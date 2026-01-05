package capsule

import (
	"io"
)

// CapsuleReader reads capsules from a stream.
type CapsuleReader struct {
	r io.Reader
}

// NewCapsuleReader creates a new CapsuleReader.
func NewCapsuleReader(r io.Reader) *CapsuleReader {
	return &CapsuleReader{r: r}
}

// ReadCapsule reads the next capsule from the stream.
// Returns the capsule or an error (including io.EOF when stream ends).
func (cr *CapsuleReader) ReadCapsule() (*Capsule, error) {
	return DecodeCapsule(cr.r)
}
