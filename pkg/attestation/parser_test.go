package attestation

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func makeInTotoStatementJSON(attestationType string, attestationData map[string]interface{}) []byte {
	stmt := map[string]interface{}{
		"_type":          "https://in-toto.io/Statement/v0.1",
		"predicateType":  "https://witness.testifysec.com/attestation-collection/v0.1",
		"predicate": map[string]interface{}{
			"attestations": []interface{}{
				map[string]interface{}{
					"type":        attestationType,
					"attestation": attestationData,
				},
			},
		},
	}
	b, _ := json.Marshal(stmt)
	return b
}

func makeDSSEEnvelopeJSON(payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	env := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     encoded,
		"signatures":  []interface{}{},
	}
	b, _ := json.Marshal(env)
	return b
}

// ---------------------------------------------------------------------------
// ParseWitnessData — direct in-toto statement path
// ---------------------------------------------------------------------------

func TestParseWitnessData_ParsesDirectInTotoStatement(t *testing.T) {
	data := makeInTotoStatementJSON("material", map[string]interface{}{
		"go.sum": map[string]interface{}{"sha256": "abc123"},
	})

	attestations, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(attestations))
	}
	if attestations[0].Type != "material" {
		t.Fatalf("expected type 'material', got %q", attestations[0].Type)
	}
}

func TestParseWitnessData_ParsesDSSEEnvelope(t *testing.T) {
	inner := makeInTotoStatementJSON("command-run", map[string]interface{}{
		"processes": []interface{}{},
	})
	data := makeDSSEEnvelopeJSON(inner)

	attestations, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing DSSE envelope: %v", err)
	}
	if len(attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(attestations))
	}
	if attestations[0].Type != "command-run" {
		t.Fatalf("expected type 'command-run', got %q", attestations[0].Type)
	}
}

func TestParseWitnessData_ReturnsErrorForInvalidJSON(t *testing.T) {
	_, err := ParseWitnessData([]byte(`not valid json`), nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseWitnessData_ReturnsErrorForMissingPayload(t *testing.T) {
	// Valid JSON object but neither a statement nor a DSSE envelope with payload
	data := []byte(`{"payloadType":"application/vnd.in-toto+json","signatures":[]}`)
	_, err := ParseWitnessData(data, nil)
	if err == nil {
		t.Fatal("expected error for missing payload field, got nil")
	}
}

func TestParseWitnessData_FiltersByAttestationType(t *testing.T) {
	stmt := map[string]interface{}{
		"predicate": map[string]interface{}{
			"attestations": []interface{}{
				map[string]interface{}{"type": "material", "attestation": map[string]interface{}{}},
				map[string]interface{}{"type": "command-run", "attestation": map[string]interface{}{}},
				map[string]interface{}{"type": "product", "attestation": map[string]interface{}{}},
			},
		},
	}
	data, _ := json.Marshal(stmt)

	attestations, err := ParseWitnessData(data, []string{"material"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attestations) != 1 {
		t.Fatalf("expected 1 attestation after filtering, got %d", len(attestations))
	}
	if attestations[0].Type != "material" {
		t.Fatalf("expected type 'material', got %q", attestations[0].Type)
	}
}

func TestParseWitnessData_ReturnsEmptySliceWhenNoAttestationsKey(t *testing.T) {
	// predicate exists but has no "attestations" key
	stmt := map[string]interface{}{
		"predicate": map[string]interface{}{
			"something_else": "value",
		},
	}
	data, _ := json.Marshal(stmt)

	attestations, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attestations) != 0 {
		t.Fatalf("expected 0 attestations, got %d", len(attestations))
	}
}

// ---------------------------------------------------------------------------
// canonicalAttestationType
// ---------------------------------------------------------------------------

func TestCanonicalAttestationType_NormalizesCommandRun(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"commandrun", "command-run"},
		{"CommandRun", "command-run"},
		{"https://witness.dev/attestations/commandrun/v0.1", "command-run"},
	}
	for _, tc := range cases {
		got := canonicalAttestationType(tc.input)
		if got != tc.expected {
			t.Errorf("canonicalAttestationType(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestCanonicalAttestationType_ExtractsLastSegmentFromURI(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://witness.dev/attestations/material/v0.1", "material"},
		{"https://witness.dev/attestations/product/v0.1", "product"},
		{"material", "material"},
		{"product", "product"},
	}
	for _, tc := range cases {
		got := canonicalAttestationType(tc.input)
		if got != tc.expected {
			t.Errorf("canonicalAttestationType(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestCanonicalAttestationType_ReturnsEmptyForBlankInput(t *testing.T) {
	if got := canonicalAttestationType(""); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// ExtractorChain — deduplication across attestations
// ---------------------------------------------------------------------------

func TestExtractorChain_DeduplicatesFilesByPath(t *testing.T) {
	attestations := []TypedAttestation{
		{
			Type: "material",
			Data: map[string]interface{}{
				"go.sum": map[string]interface{}{"sha256": "aaa"},
			},
		},
		{
			Type: "material",
			Data: map[string]interface{}{
				// Same path as above — must be deduplicated
				"go.sum": map[string]interface{}{"sha256": "aaa"},
			},
		},
	}
	chain := NewExtractorChain()
	files := chain.ExtractAll(attestations, nil)
	if len(files) != 1 {
		t.Fatalf("expected 1 deduplicated file, got %d", len(files))
	}
}

func TestExtractorChain_FiltersToRequestedAttestationTypes(t *testing.T) {
	attestations := []TypedAttestation{
		{
			Type: "material",
			Data: map[string]interface{}{
				"go.sum": map[string]interface{}{"sha256": "aaa"},
			},
		},
		{
			Type: "product",
			Data: map[string]interface{}{
				"bin/app": map[string]interface{}{"sha256": "bbb"},
			},
		},
	}
	chain := NewExtractorChain()
	// Only request product files
	files := chain.ExtractAll(attestations, []string{"product"})
	if len(files) != 1 {
		t.Fatalf("expected 1 file (product only), got %d", len(files))
	}
	if files[0].Path != "bin/app" {
		t.Fatalf("expected path 'bin/app', got %q", files[0].Path)
	}
}
