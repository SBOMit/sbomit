package attestation

import (
	"encoding/json"
	"testing"
)

func TestCanonicalAttestationType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"simple", "material", "material"},
		{"uri style", "https://in-toto.io/attestation/material/v1", "material"},
		{"commandrun maps to command-run", "commandrun", "command-run"},
		{"uri commandrun", "https://in-toto.io/attestation/commandrun/v1", "command-run"},
		{"mixed case", "Material", "material"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := canonicalAttestationType(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestExtractAttestations(t *testing.T) {
	predicateJSON := `{
		"attestations": [
			{
				"type": "https://in-toto.io/attestation/material/v1",
				"attestation": {
					"materials": {
						"file.txt": {"sha256": "abcdef"}
					}
				}
			},
			{
				"type": "commandrun",
				"attestation": {
					"cmd": "ls -l"
				}
			}
		]
	}`

	var predicate map[string]interface{}
	if err := json.Unmarshal([]byte(predicateJSON), &predicate); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	t.Run("no filter", func(t *testing.T) {
		res, err := extractAttestations(predicate, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 2 {
			t.Errorf("expected 2 attestations, got %d", len(res))
		}
		if res[0].Type != "material" {
			t.Errorf("expected type 'material', got %q", res[0].Type)
		}
		if res[1].Type != "command-run" {
			t.Errorf("expected type 'command-run', got %q", res[1].Type)
		}
	})

	t.Run("with filter", func(t *testing.T) {
		res, err := extractAttestations(predicate, []string{"material"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 1 {
			t.Errorf("expected 1 attestation, got %d", len(res))
		}
		if res[0].Type != "material" {
			t.Errorf("expected type 'material', got %q", res[0].Type)
		}
	})
}
