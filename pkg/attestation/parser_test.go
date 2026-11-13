package attestation

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseWitnessDataDirectInTotoStatement(t *testing.T) {
	statement := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://witness.dev/attestations/v0.1",
		Predicate: map[string]interface{}{
			"attestations": []interface{}{
				map[string]interface{}{
					"type": "https://in-toto.io/attestation/material/v1",
					"attestation": map[string]interface{}{
						"materials": map[string]interface{}{
							"/workspace/main.go": map[string]interface{}{
								"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
							},
						},
					},
				},
				map[string]interface{}{
					"type": "commandrun",
					"attestation": map[string]interface{}{
						"cmd": "go build .",
					},
				},
			},
		},
	}

	data, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	attestations, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing direct in-toto statement: %v", err)
	}

	if len(attestations) != 2 {
		t.Fatalf("expected 2 attestations, got %d", len(attestations))
	}
	if attestations[0].Type != "material" {
		t.Errorf("expected normalized type 'material', got %q", attestations[0].Type)
	}
	if attestations[1].Type != "command-run" {
		t.Errorf("expected normalized type 'command-run', got %q", attestations[1].Type)
	}
}

func TestParseWitnessDataDSSEEnvelope(t *testing.T) {
	innerStatement := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://witness.dev/attestations/v0.1",
		Predicate: map[string]interface{}{
			"attestations": []interface{}{
				map[string]interface{}{
					"type": "product",
					"attestation": map[string]interface{}{
						"products": map[string]interface{}{
							"/bin/app": map[string]interface{}{
								"sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
							},
						},
					},
				},
			},
		},
	}

	innerBytes, err := json.Marshal(innerStatement)
	if err != nil {
		t.Fatalf("marshal inner statement: %v", err)
	}

	encodedPayload := base64.StdEncoding.EncodeToString(innerBytes)

	envelopeJSON := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     encodedPayload,
		"signatures": []map[string]string{
			{
				"keyid": "key-1",
				"sig":   "sig-data",
			},
		},
	}

	data, err := json.Marshal(envelopeJSON)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	attestations, err := ParseWitnessData(data, []string{"product"})
	if err != nil {
		t.Fatalf("unexpected error parsing DSSE envelope: %v", err)
	}

	if len(attestations) != 1 {
		t.Fatalf("expected 1 product attestation, got %d", len(attestations))
	}
	if attestations[0].Type != "product" {
		t.Fatalf("expected type 'product', got %q", attestations[0].Type)
	}
}

func TestParseWitnessDataMalformedPayloadErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		errContains string
	}{
		{
			name:        "invalid JSON",
			input:       `{not-valid-json`,
			errContains: "failed to unmarshal attestation JSON",
		},
		{
			name:        "missing payload",
			input:       `{"payloadType":"application/vnd.in-toto+json","signatures":[]}`,
			errContains: "missing payload in attestation JSON",
		},
		{
			name:        "corrupted base64 payload",
			input:       `{"payloadType":"application/vnd.in-toto+json","payload":"not-valid-base64===","signatures":[]}`,
			errContains: "base64 decoding failed",
		},
		{
			name:        "malformed inner in-toto JSON",
			input:       `{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString([]byte(`{bad-json`)) + `","signatures":[]}`,
			errContains: "failed to unmarshal in-toto statement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWitnessData([]byte(tt.input), nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errContains)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got %q", tt.errContains, err.Error())
			}
		})
	}
}

func TestCanonicalAttestationType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"material", "material"},
		{"MATERIAL", "material"},
		{"https://in-toto.io/attestation/material/v1", "material"},
		{"https://witness.dev/attestations/product/v0.1", "product"},
		{"commandrun", "command-run"},
		{"COMMANDRUN", "command-run"},
		{"https://in-toto.io/attestation/commandrun/v1", "command-run"},
		{"network-trace", "network-trace"},
	}

	for _, tt := range tests {
		got := canonicalAttestationType(tt.input)
		if got != tt.expected {
			t.Errorf("canonicalAttestationType(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractAttestationsTypeFilter(t *testing.T) {
	predicate := map[string]interface{}{
		"attestations": []interface{}{
			map[string]interface{}{
				"type": "material",
				"attestation": map[string]interface{}{
					"materials": map[string]interface{}{},
				},
			},
			map[string]interface{}{
				"type": "product",
				"attestation": map[string]interface{}{
					"products": map[string]interface{}{},
				},
			},
		},
	}

	filtered, err := extractAttestations(predicate, []string{"product"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered attestation, got %d", len(filtered))
	}
	if filtered[0].Type != "product" {
		t.Fatalf("expected 'product', got %q", filtered[0].Type)
	}
}
