package capsule

import (
	"bytes"
	"testing"
)

func TestDebugDecode(t *testing.T) {
	// Test case: 0x40 0x0A 0x01 0x02
	input := []byte{0x40, 0x0A, 0x01, 0x02}
	r := bytes.NewReader(input)
	
	cap, err := DecodeCapsule(r)
	t.Logf("Input: %x", input)
	t.Logf("Result: cap=%+v, err=%v", cap, err)
	
	// Test case: 0x40 0x00
	input2 := []byte{0x40, 0x00}
	r2 := bytes.NewReader(input2)
	cap2, err2 := DecodeCapsule(r2)
	t.Logf("Input2: %x", input2)
	t.Logf("Result2: cap=%+v, err=%v", cap2, err2)
}
