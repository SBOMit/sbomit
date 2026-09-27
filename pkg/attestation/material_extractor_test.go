package attestation

import (
	"sort"
	"testing"
)

func TestMaterialExtractor(t *testing.T) {
	extractor := NewMaterialExtractor()
	
	if extractor.Name() != "material" {
		t.Errorf("Expected Name 'material', got %s", extractor.Name())
	}

	t.Run("Valid materials map", func(t *testing.T) {
		data := map[string]interface{}{
			"materials": map[string]interface{}{
				"src/main.go": map[string]interface{}{
					"sha256": "1234abcd",
				},
				"src/util.go": map[string]interface{}{
					"sha1": "5678efgh",
				},
			},
		}

		res := extractor.Extract(data)
		if len(res) != 2 {
			t.Fatalf("Expected 2 files extracted, got %d", len(res))
		}

		// Sort to ensure deterministic order
		sort.Slice(res, func(i, j int) bool {
			return res[i].Path < res[j].Path
		})

		if res[0].Path != "src/main.go" || res[0].Hashes["sha256"] != "1234abcd" {
			t.Errorf("Unexpected result for src/main.go: %+v", res[0])
		}
		if res[1].Path != "src/util.go" || res[1].Hashes["sha1"] != "5678efgh" {
			t.Errorf("Unexpected result for src/util.go: %+v", res[1])
		}
	})

	t.Run("Empty input", func(t *testing.T) {
		data := map[string]interface{}{}
		res := extractor.Extract(data)
		if len(res) != 0 {
			t.Errorf("Expected 0 files extracted from empty input, got %d", len(res))
		}
	})

	t.Run("Flat materials structure", func(t *testing.T) {
		data := map[string]interface{}{
			"flatfile.txt": map[string]interface{}{
				"sha256": "aaaa",
			},
			"command": "ignore_me",
		}

		res := extractor.Extract(data)
		if len(res) != 1 {
			t.Fatalf("Expected 1 file extracted, got %d", len(res))
		}
		if res[0].Path != "flatfile.txt" || res[0].Hashes["sha256"] != "aaaa" {
			t.Errorf("Unexpected result: %+v", res[0])
		}
	})
}
