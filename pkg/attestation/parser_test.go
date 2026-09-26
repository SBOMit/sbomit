package attestation

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// buildInTotoStatement returns a minimal in-toto statement JSON as bytes.
func buildInTotoStatement(attestations []map[string]interface{}) []byte {
	stmt := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
		"subject":       []interface{}{},
		"predicate": map[string]interface{}{
			"name":         "test-build",
			"attestations": attestations,
		},
	}
	b, _ := json.Marshal(stmt)
	return b
}

// buildDSSEEnvelope wraps a payload (bytes) as a base64-encoded DSSE envelope.
func buildDSSEEnvelope(payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     encoded,
		"signatures":  []interface{}{},
	}
	b, _ := json.Marshal(envelope)
	return b
}

// --- ParseWitnessData ---

func TestParseWitnessData_DirectStatement_ReturnsAttestations(t *testing.T) {
	data := buildInTotoStatement([]map[string]interface{}{
		{
			"type": "https://witness.dev/attestations/material/v0.1",
			"attestation": map[string]interface{}{
				"src/main.go": map[string]interface{}{
					"sha256": "abc123",
				},
			},
		},
	})

	atts, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(atts))
	}
	if atts[0].Type != "material" {
		t.Errorf("expected type 'material', got %q", atts[0].Type)
	}
}

func TestParseWitnessData_DSSEEnvelope_ReturnsAttestations(t *testing.T) {
	inner := buildInTotoStatement([]map[string]interface{}{
		{
			"type": "https://witness.dev/attestations/product/v0.1",
			"attestation": map[string]interface{}{
				"bin/app": map[string]interface{}{
					"sha256": "deadbeef",
				},
			},
		},
	})
	data := buildDSSEEnvelope(inner)

	atts, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(atts))
	}
	if atts[0].Type != "product" {
		t.Errorf("expected type 'product', got %q", atts[0].Type)
	}
}

func TestParseWitnessData_TypeFilter_OnlyReturnsMatchingTypes(t *testing.T) {
	data := buildInTotoStatement([]map[string]interface{}{
		{"type": "https://witness.dev/attestations/material/v0.1", "attestation": map[string]interface{}{"a.go": map[string]interface{}{"sha256": "111"}}},
		{"type": "https://witness.dev/attestations/product/v0.1", "attestation": map[string]interface{}{"out": map[string]interface{}{"sha256": "222"}}},
	})

	atts, err := ParseWitnessData(data, []string{"material"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("expected 1 attestation after filtering, got %d", len(atts))
	}
	if atts[0].Type != "material" {
		t.Errorf("expected 'material', got %q", atts[0].Type)
	}
}

func TestParseWitnessData_TypeFilter_NoMatch_ReturnsEmpty(t *testing.T) {
	data := buildInTotoStatement([]map[string]interface{}{
		{"type": "https://witness.dev/attestations/material/v0.1", "attestation": map[string]interface{}{}},
	})

	atts, err := ParseWitnessData(data, []string{"product"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(atts))
	}
}

func TestParseWitnessData_EmptyFilter_ReturnsAll(t *testing.T) {
	data := buildInTotoStatement([]map[string]interface{}{
		{"type": "https://witness.dev/attestations/material/v0.1", "attestation": map[string]interface{}{}},
		{"type": "https://witness.dev/attestations/product/v0.1", "attestation": map[string]interface{}{}},
		{"type": "https://witness.dev/attestations/command-run/v0.1", "attestation": map[string]interface{}{}},
	})

	atts, err := ParseWitnessData(data, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 3 {
		t.Errorf("expected 3 attestations, got %d", len(atts))
	}
}

func TestParseWitnessData_EmptyAttestationsList_ReturnsEmpty(t *testing.T) {
	data := buildInTotoStatement([]map[string]interface{}{})

	atts, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(atts))
	}
}

func TestParseWitnessData_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := ParseWitnessData([]byte(`not valid json`), nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseWitnessData_DSSEMissingPayload_ReturnsError(t *testing.T) {
	envelope := `{"payloadType":"application/vnd.in-toto+json","signatures":[]}`
	_, err := ParseWitnessData([]byte(envelope), nil)
	if err == nil {
		t.Fatal("expected error for missing payload, got nil")
	}
}

func TestParseWitnessData_AttestationDataIsPresent(t *testing.T) {
	data := buildInTotoStatement([]map[string]interface{}{
		{
			"type": "https://witness.dev/attestations/material/v0.1",
			"attestation": map[string]interface{}{
				"src/main.go": map[string]interface{}{
					"sha256": "cafebabe",
				},
			},
		},
	})

	atts, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) == 0 {
		t.Fatal("expected at least 1 attestation")
	}
	if atts[0].Data == nil {
		t.Fatal("expected attestation Data to be populated")
	}
	if _, ok := atts[0].Data["src/main.go"]; !ok {
		t.Error("expected 'src/main.go' key in attestation data")
	}
}

func TestParseWitnessData_MultipleAttestationsSameType(t *testing.T) {
	data := buildInTotoStatement([]map[string]interface{}{
		{"type": "https://witness.dev/attestations/material/v0.1", "attestation": map[string]interface{}{"a.go": map[string]interface{}{"sha256": "111"}}},
		{"type": "https://witness.dev/attestations/material/v0.1", "attestation": map[string]interface{}{"b.go": map[string]interface{}{"sha256": "222"}}},
	})

	atts, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 2 {
		t.Errorf("expected 2 attestations, got %d", len(atts))
	}
}

// --- ParseWitnessFile ---

func TestParseWitnessFile_FileNotFound_ReturnsError(t *testing.T) {
	_, err := ParseWitnessFile("/nonexistent/path/attestation.json", nil)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestParseWitnessFile_ValidFile_ReturnsAttestations(t *testing.T) {
	// Write a temp file with a valid in-toto statement
	data := buildInTotoStatement([]map[string]interface{}{
		{"type": "https://witness.dev/attestations/material/v0.1", "attestation": map[string]interface{}{"main.go": map[string]interface{}{"sha256": "abc"}}},
	})
	f, err := os.CreateTemp(t.TempDir(), "attestation-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()

	atts, err := ParseWitnessFile(f.Name(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 1 {
		t.Errorf("expected 1 attestation, got %d", len(atts))
	}
}

func TestParseWitnessFile_SampleAttestation_ParsesSuccessfully(t *testing.T) {
	// Integration test against the real sample file shipped with the repo
	samplePath := filepath.Join("..", "..", "test", "sample-attestation.json")
	if _, err := os.Stat(samplePath); os.IsNotExist(err) {
		t.Skip("sample-attestation.json not found, skipping integration test")
	}

	atts, err := ParseWitnessFile(samplePath, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing sample attestation: %v", err)
	}
	if len(atts) == 0 {
		t.Error("expected at least one attestation from sample file")
	}
}

func TestParseWitnessFile_SampleAttestation_ContainsMaterial(t *testing.T) {
	samplePath := filepath.Join("..", "..", "test", "sample-attestation.json")
	if _, err := os.Stat(samplePath); os.IsNotExist(err) {
		t.Skip("sample-attestation.json not found, skipping integration test")
	}

	atts, err := ParseWitnessFile(samplePath, []string{"material"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) == 0 {
		t.Error("expected at least one material attestation in sample file")
	}
	for _, a := range atts {
		if a.Type != "material" {
			t.Errorf("expected only 'material' type, got %q", a.Type)
		}
	}
}

// --- canonicalAttestationType ---

func TestCanonicalAttestationType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// URI-style full type names
		{"https://witness.dev/attestations/material/v0.1", "material"},
		{"https://witness.dev/attestations/product/v0.1", "product"},
		{"https://witness.dev/attestations/command-run/v0.1", "command-run"},
		{"https://witness.dev/attestations/network-trace/v0.1", "network-trace"},
		// Shorthand names passed through unchanged
		{"material", "material"},
		{"product", "product"},
		{"network-trace", "network-trace"},
		// commandrun alias
		{"commandrun", "command-run"},
		{"https://witness.dev/attestations/commandrun/v0.1", "command-run"},
		// Case insensitivity
		{"MATERIAL", "material"},
		{"Material", "material"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := canonicalAttestationType(tc.input)
			if got != tc.want {
				t.Errorf("canonicalAttestationType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCanonicalAttestationType_Empty_ReturnsEmpty(t *testing.T) {
	if got := canonicalAttestationType(""); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// --- normalizeAttestationType ---

func TestNormalizeAttestationType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Material", "material"},
		{"  material  ", "material"},
		{"COMMAND-RUN", "command-run"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeAttestationType(tc.input)
			if got != tc.want {
				t.Errorf("normalizeAttestationType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
