package attestation

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDecodeBase64Any(t *testing.T) {
	tests := []struct {
		name     string
		encoding *base64.Encoding
	}{
		{"RawURLEncoding (DSSE standard)", base64.RawURLEncoding},
		{"URLEncoding", base64.URLEncoding},
		{"StdEncoding", base64.StdEncoding},
		{"RawStdEncoding", base64.RawStdEncoding},
	}

	// 0xFF bytes encode to "////" in StdEncoding and "____" in RawURLEncoding,ensuring the variants are non-interchangeable
	original := []byte{0xff, 0xff, 0xff}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.encoding.EncodeToString(original)
			got, err := decodeBase64Any(encoded)
			if err != nil {
				t.Fatalf("decodeBase64Any(%q) failed: %v", encoded, err)
			}
			if !bytes.Equal(got, original) {
				t.Errorf("decodeBase64Any(%q) = %v; want %v", encoded, got, original)
			}
		})
	}
}

func TestDecodeBase64Any_NoPadding(t *testing.T) {
	// DSSE payloads use base64url without padding; StdEncoding rejects these.
	original := []byte(`{"a":1}`)

	encoded := base64.RawURLEncoding.EncodeToString(original)
	got, err := decodeBase64Any(encoded)
	if err != nil {
		t.Fatalf("decodeBase64Any(%q) failed: %v", encoded, err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("decodeBase64Any(%q) = %q; want %q", encoded, got, original)
	}
}
