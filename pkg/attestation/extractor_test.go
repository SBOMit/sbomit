package attestation

import (
	"testing"
)

func TestExtractAll_TypeFilterNormalization(t *testing.T) {
	attestations := []TypedAttestation{
		{
			Type: "command-run",
			Data: map[string]interface{}{
				"processes": []interface{}{
					map[string]interface{}{
						"openedfiles": map[string]interface{}{
							"/usr/lib/python3/site-packages/requests-2.28.0.dist-info/METADATA": map[string]interface{}{
								"sha256": "abc123",
							},
						},
					},
				},
			},
		},
	}

	chain := NewExtractorChain()

	tests := []struct {
		name       string
		typeFilter []string
	}{
		{"exact lowercase", []string{"command-run"}},
		{"mixed case", []string{"Command-Run"}},
		{"uppercase", []string{"COMMAND-RUN"}},
		{"with whitespace", []string{"  command-run  "}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := chain.ExtractAll(attestations, tt.typeFilter)
			if len(files) == 0 {
				t.Errorf("ExtractAll with typeFilter %v returned no files; want at least 1", tt.typeFilter)
			}
		})
	}
}
