package capsule

import (
	"bytes"
	"io"
	"testing"
)

// TestVarintRoundtrip tests encoding and decoding for various values.
func TestVarintRoundtrip(t *testing.T) {
	testCases := []struct {
		name  string
		value uint64
		bytes int
	}{
		{"zero", 0, 1},
		{"one", 1, 1},
		{"max-1-byte", 0x3F, 1},
		{"min-2-byte", 0x40, 2},
		{"typical-mtu", 1300, 2},
		{"max-2-byte", 0x3FFF, 2},
		{"min-4-byte", 0x4000, 4},
		{"max-4-byte", 0x3FFFFFFF, 4},
		{"min-8-byte", 0x40000000, 8},
		{"large-8-byte", 0x123456789ABCDEF, 8},
		{"max-8-byte", 0x3FFFFFFFFFFFFFFF, 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded, n := EncodeVarint(tc.value)
			if n != tc.bytes {
				t.Errorf("EncodeVarint(%d) returned %d bytes, expected %d", tc.value, n, tc.bytes)
			}
			if len(encoded) != tc.bytes {
				t.Errorf("EncodeVarint(%d) produced %d bytes, expected %d", tc.value, len(encoded), tc.bytes)
			}

			// Decode
			r := bytes.NewReader(encoded)
			decoded, bytesRead, err := DecodeVarint(r)
			if err != nil {
				t.Fatalf("DecodeVarint failed: %v", err)
			}
			if bytesRead != tc.bytes {
				t.Errorf("DecodeVarint read %d bytes, expected %d", bytesRead, tc.bytes)
			}
			if decoded != tc.value {
				t.Errorf("DecodeVarint(%v) = %d, expected %d", encoded, decoded, tc.value)
			}

			// Verify no bytes left
			if r.Len() != 0 {
				t.Errorf("DecodeVarint left %d bytes unread", r.Len())
			}
		})
	}
}

// TestVarintBoundaries tests edge cases for each size class.
func TestVarintBoundaries(t *testing.T) {
	boundaries := []uint64{
		0x00,               // Min 1-byte
		0x3F,               // Max 1-byte
		0x40,               // Min 2-byte
		0x3FFF,             // Max 2-byte
		0x4000,             // Min 4-byte
		0x3FFFFFFF,         // Max 4-byte
		0x40000000,         // Min 8-byte
		0x3FFFFFFFFFFFFFFF, // Max 8-byte
	}

	for _, value := range boundaries {
		encoded, _ := EncodeVarint(value)
		r := bytes.NewReader(encoded)
		decoded, _, err := DecodeVarint(r)
		if err != nil {
			t.Errorf("Boundary test failed for %d: %v", value, err)
		}
		if decoded != value {
			t.Errorf("Boundary test: decoded %d, expected %d", decoded, value)
		}
	}
}

// TestVarintEncodingFormat tests the actual byte format according to RFC 9000.
func TestVarintEncodingFormat(t *testing.T) {
	testCases := []struct {
		value    uint64
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{63, []byte{0x3F}},
		{64, []byte{0x40, 0x40}},
		{16383, []byte{0x7F, 0xFF}},
		{16384, []byte{0x80, 0x00, 0x40, 0x00}},
		{1073741823, []byte{0xBF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range testCases {
		encoded, _ := EncodeVarint(tc.value)
		if !bytes.Equal(encoded, tc.expected) {
			t.Errorf("EncodeVarint(%d) = %x, expected %x", tc.value, encoded, tc.expected)
		}
	}
}

// TestVarintDecodeErrors tests error cases for DecodeVarint.
func TestVarintDecodeErrors(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"truncated-2-byte", []byte{0x40}},
		{"truncated-4-byte", []byte{0x80, 0x00, 0x00}},
		{"truncated-8-byte", []byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewReader(tc.input)
			_, _, err := DecodeVarint(r)
			if err == nil {
				t.Errorf("DecodeVarint(%x) should have returned an error", tc.input)
			}
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				// Wrapped errors are acceptable
				t.Logf("DecodeVarint error: %v (expected EOF-related error)", err)
			}
		})
	}
}

// TestVarintDecodeFromEOF tests DecodeVarint with an empty reader.
func TestVarintDecodeFromEOF(t *testing.T) {
	r := bytes.NewReader([]byte{})
	_, _, err := DecodeVarint(r)
	if err == nil {
		t.Errorf("DecodeVarint on empty reader should return an error")
	}
	// Error should be EOF-related (may be wrapped)
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Logf("DecodeVarint error: %v (expected EOF-related error)", err)
	}
}

// TestVarintMultipleInSequence tests decoding multiple varints from a single stream.
func TestVarintMultipleInSequence(t *testing.T) {
	// Create a stream with multiple varints
	var buf bytes.Buffer
	values := []uint64{0, 63, 64, 1300, 16383, 16384}

	for _, v := range values {
		encoded, _ := EncodeVarint(v)
		buf.Write(encoded)
	}

	// Decode them in sequence
	r := bytes.NewReader(buf.Bytes())
	for i, expected := range values {
		decoded, _, err := DecodeVarint(r)
		if err != nil {
			t.Fatalf("DecodeVarint #%d failed: %v", i, err)
		}
		if decoded != expected {
			t.Errorf("DecodeVarint #%d = %d, expected %d", i, decoded, expected)
		}
	}

	// Verify stream is fully consumed
	if r.Len() != 0 {
		t.Errorf("Stream has %d bytes remaining after decoding", r.Len())
	}
}

// BenchmarkVarintEncode1Byte benchmarks encoding 1-byte varints.
func BenchmarkVarintEncode1Byte(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncodeVarint(42)
	}
}

// BenchmarkVarintEncode2Byte benchmarks encoding 2-byte varints.
func BenchmarkVarintEncode2Byte(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncodeVarint(1300)
	}
}

// BenchmarkVarintEncode4Byte benchmarks encoding 4-byte varints.
func BenchmarkVarintEncode4Byte(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncodeVarint(100000)
	}
}

// BenchmarkVarintDecode2Byte benchmarks decoding 2-byte varints.
func BenchmarkVarintDecode2Byte(b *testing.B) {
	encoded, _ := EncodeVarint(1300)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encoded)
		DecodeVarint(r)
	}
}
