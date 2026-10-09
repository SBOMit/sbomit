package attestation

import (
	"testing"
)

type mockExtractor struct {
	name string
}

func (m *mockExtractor) Name() string {
	return m.name
}

func (m *mockExtractor) Extract(data map[string]interface{}) []FileInfo {
	return []FileInfo{{Path: m.name + "_file.txt"}}
}

func TestExtractorChain(t *testing.T) {
	chain := NewExtractorChain()

	// Test default registration
	types := chain.SupportedTypes()
	if len(types) != 3 {
		t.Errorf("Expected 3 default extractors, got %d", len(types))
	}

	// Register a mock
	chain.RegisterExtractor(&mockExtractor{name: "mock"})
	types = chain.SupportedTypes()
	if len(types) != 4 {
		t.Errorf("Expected 4 extractors after registering mock, got %d", len(types))
	}

	// Check getting extractor
	e, ok := chain.GetExtractor("mock")
	if !ok {
		t.Errorf("Failed to get registered extractor")
	}
	if e.Name() != "mock" {
		t.Errorf("Expected extractor name 'mock', got %s", e.Name())
	}
}

func TestExtractAll(t *testing.T) {
	chain := &ExtractorChain{
		extractors: make(map[string]Extractor),
	}
	chain.RegisterExtractor(&mockExtractor{name: "mock1"})
	chain.RegisterExtractor(&mockExtractor{name: "mock2"})

	attestations := []TypedAttestation{
		{
			Type: "mock1",
			Data: nil,
		},
		{
			Type: "mock2",
			Data: nil,
		},
		{
			Type: "unsupported",
			Data: nil,
		},
	}

	t.Run("Extract all without filter", func(t *testing.T) {
		res := chain.ExtractAll(attestations, nil)
		if len(res) != 2 {
			t.Errorf("Expected 2 files, got %d", len(res))
		}
	})

	t.Run("Extract with filter", func(t *testing.T) {
		res := chain.ExtractAll(attestations, []string{"mock1"})
		if len(res) != 1 {
			t.Errorf("Expected 1 file, got %d", len(res))
		}
		if res[0].Path != "mock1_file.txt" {
			t.Errorf("Expected mock1_file.txt, got %s", res[0].Path)
		}
	})
}
