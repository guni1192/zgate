package capsule

import (
	"bytes"
	"sync"
	"testing"
)

// TestCapsuleEncodeDecode tests basic capsule encoding/decoding.
func TestCapsuleEncodeDecode(t *testing.T) {
	testCases := []struct {
		name    string
		capsule *Capsule
	}{
		{
			name: "empty-value",
			capsule: &Capsule{
				Type:   CapsuleTypeIPPacket,
				Length: 0,
				Value:  []byte{},
			},
		},
		{
			name: "small-packet",
			capsule: &Capsule{
				Type:   CapsuleTypeIPPacket,
				Length: 4,
				Value:  []byte{0x45, 0x00, 0x00, 0x1C},
			},
		},
		{
			name: "address-assign",
			capsule: &Capsule{
				Type:   CapsuleTypeAddressAssign,
				Length: 10,
				Value:  make([]byte, 10),
			},
		},
		{
			name: "mtu-sized",
			capsule: &Capsule{
				Type:   CapsuleTypeIPPacket,
				Length: 1300,
				Value:  make([]byte, 1300),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded, err := EncodeCapsule(tc.capsule)
			if err != nil {
				t.Fatalf("EncodeCapsule failed: %v", err)
			}

			// Decode
			r := bytes.NewReader(encoded)
			decoded, err := DecodeCapsule(r)
			if err != nil {
				t.Fatalf("DecodeCapsule failed: %v", err)
			}

			// Verify
			if decoded.Type != tc.capsule.Type {
				t.Errorf("Type mismatch: got %d, expected %d", decoded.Type, tc.capsule.Type)
			}
			if decoded.Length != tc.capsule.Length {
				t.Errorf("Length mismatch: got %d, expected %d", decoded.Length, tc.capsule.Length)
			}
			if !bytes.Equal(decoded.Value, tc.capsule.Value) {
				t.Errorf("Value mismatch: got %v, expected %v", decoded.Value, tc.capsule.Value)
			}

			// Verify stream fully consumed
			if r.Len() != 0 {
				t.Errorf("Stream has %d bytes remaining", r.Len())
			}
		})
	}
}

// TestCapsuleInvalidLength tests capsules with mismatched Length field.
func TestCapsuleInvalidLength(t *testing.T) {
	invalidCapsule := &Capsule{
		Type:   CapsuleTypeIPPacket,
		Length: 10,          // Declared length
		Value:  []byte{1, 2}, // Actual length: 2
	}

	_, err := EncodeCapsule(invalidCapsule)
	if err == nil {
		t.Error("EncodeCapsule should fail on length mismatch")
	}
}

// TestCapsuleNil tests encoding a nil capsule.
func TestCapsuleNil(t *testing.T) {
	_, err := EncodeCapsule(nil)
	if err == nil {
		t.Error("EncodeCapsule should fail on nil capsule")
	}
}

// TestCapsuleStreamMultiple tests decoding multiple capsules from a single stream.
func TestCapsuleStreamMultiple(t *testing.T) {
	// Create stream with 100 capsules
	var buf bytes.Buffer
	capsules := make([]*Capsule, 100)

	for i := 0; i < 100; i++ {
		capsules[i] = &Capsule{
			Type:   CapsuleTypeIPPacket,
			Length: uint64(i % 256),
			Value:  make([]byte, i%256),
		}
		// Fill with pattern
		for j := range capsules[i].Value {
			capsules[i].Value[j] = byte(j)
		}

		encoded, _ := EncodeCapsule(capsules[i])
		buf.Write(encoded)
	}

	// Decode all capsules
	r := bytes.NewReader(buf.Bytes())
	for i := 0; i < 100; i++ {
		decoded, err := DecodeCapsule(r)
		if err != nil {
			t.Fatalf("DecodeCapsule #%d failed: %v", i, err)
		}

		if decoded.Type != capsules[i].Type {
			t.Errorf("#%d: Type mismatch", i)
		}
		if decoded.Length != capsules[i].Length {
			t.Errorf("#%d: Length mismatch: got %d, expected %d", i, decoded.Length, capsules[i].Length)
		}
		if !bytes.Equal(decoded.Value, capsules[i].Value) {
			t.Errorf("#%d: Value mismatch", i)
		}
	}

	// Verify stream fully consumed
	if r.Len() != 0 {
		t.Errorf("Stream has %d bytes remaining after 100 capsules", r.Len())
	}
}

// TestCapsuleDecodeErrors tests error cases for DecodeCapsule.
func TestCapsuleDecodeErrors(t *testing.T) {
	testCases := []struct {
		name        string
		input       []byte
		expectError bool
	}{
		{"empty", []byte{}, true},
		{"type-only", []byte{0x40}, true},
		{"truncated-length", []byte{0x40, 0x41}, true},              // Type=0x40, 2-byte length started but incomplete
		{"truncated-value", []byte{0x40, 0x03, 0x01}, true},         // Length=3, but only 1 byte
		{"valid-short", []byte{0x40, 0x02, 0x01, 0x02}, false},      // Valid: Type=0x40, Length=2, Value=[0x01, 0x02]
		{"valid-zero-length", []byte{0x01, 0x00}, false},            // Valid: Type=0x01 (ADDRESS_ASSIGN), Length=0
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewReader(tc.input)
			_, err := DecodeCapsule(r)
			if tc.expectError && err == nil {
				t.Errorf("DecodeCapsule(%x) should have returned an error", tc.input)
			}
			if !tc.expectError && err != nil {
				t.Errorf("DecodeCapsule(%x) should have succeeded, got error: %v", tc.input, err)
			}
		})
	}
}

// TestCapsuleReaderWriter tests CapsuleReader and CapsuleWriter.
func TestCapsuleReaderWriter(t *testing.T) {
	var buf bytes.Buffer
	writer := NewCapsuleWriter(&buf)
	reader := NewCapsuleReader(&buf)

	// Write capsules
	capsulesToWrite := []*Capsule{
		{Type: CapsuleTypeIPPacket, Length: 4, Value: []byte{1, 2, 3, 4}},
		{Type: CapsuleTypeAddressAssign, Length: 2, Value: []byte{5, 6}},
		{Type: CapsuleTypeIPPacket, Length: 0, Value: []byte{}},
	}

	for _, cap := range capsulesToWrite {
		if err := writer.WriteCapsule(cap); err != nil {
			t.Fatalf("WriteCapsule failed: %v", err)
		}
	}

	// Read capsules
	for i, expected := range capsulesToWrite {
		decoded, err := reader.ReadCapsule()
		if err != nil {
			t.Fatalf("ReadCapsule #%d failed: %v", i, err)
		}

		if decoded.Type != expected.Type {
			t.Errorf("#%d: Type mismatch", i)
		}
		if decoded.Length != expected.Length {
			t.Errorf("#%d: Length mismatch", i)
		}
		if !bytes.Equal(decoded.Value, expected.Value) {
			t.Errorf("#%d: Value mismatch", i)
		}
	}

	// Verify EOF after reading all (may be wrapped)
	_, err := reader.ReadCapsule()
	if err == nil {
		t.Error("Expected error (EOF) after reading all capsules")
	}
}

// TestCapsuleWriterConcurrency tests thread-safety of CapsuleWriter.
func TestCapsuleWriterConcurrency(t *testing.T) {
	var buf bytes.Buffer
	writer := NewCapsuleWriter(&buf)

	const numGoroutines = 10
	const capsulesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Write capsules concurrently
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < capsulesPerGoroutine; i++ {
				cap := &Capsule{
					Type:   CapsuleTypeIPPacket,
					Length: 2,
					Value:  []byte{byte(id), byte(i)},
				}
				if err := writer.WriteCapsule(cap); err != nil {
					t.Errorf("WriteCapsule failed: %v", err)
				}
			}
		}(g)
	}

	wg.Wait()

	// Verify all capsules were written
	totalExpected := numGoroutines * capsulesPerGoroutine
	reader := NewCapsuleReader(&buf)
	count := 0

	for {
		_, err := reader.ReadCapsule()
		if err != nil {
			// EOF or wrapped EOF is expected at end
			break
		}
		count++
	}

	if count != totalExpected {
		t.Errorf("Expected %d capsules, got %d", totalExpected, count)
	}
}

// BenchmarkCapsuleEncode benchmarks capsule encoding.
func BenchmarkCapsuleEncode(b *testing.B) {
	cap := &Capsule{
		Type:   CapsuleTypeIPPacket,
		Length: 1300,
		Value:  make([]byte, 1300),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeCapsule(cap)
	}
}

// BenchmarkCapsuleDecode benchmarks capsule decoding.
func BenchmarkCapsuleDecode(b *testing.B) {
	cap := &Capsule{
		Type:   CapsuleTypeIPPacket,
		Length: 1300,
		Value:  make([]byte, 1300),
	}
	encoded, _ := EncodeCapsule(cap)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		DecodeCapsule(r)
	}
}
