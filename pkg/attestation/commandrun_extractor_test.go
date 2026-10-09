package attestation

import (
	"sort"
	"testing"
)

func TestCommandRunExtractor(t *testing.T) {
	extractor := NewCommandRunExtractor()

	if extractor.Name() != "command-run" {
		t.Errorf("Expected Name 'command-run', got %s", extractor.Name())
	}

	t.Run("Valid processes map", func(t *testing.T) {
		data := map[string]interface{}{
			"processes": []interface{}{
				map[string]interface{}{
					"openedfiles": map[string]interface{}{
						"src/main.go": map[string]interface{}{
							"sha256": "1111abcd",
						},
					},
				},
				map[string]interface{}{
					"openedfiles": map[string]interface{}{
						"src/util.go": map[string]interface{}{
							"sha1": "2222efgh",
						},
						"src/main.go": map[string]interface{}{
							"sha256": "1111abcd", // duplicate should be handled
						},
					},
				},
			},
		}

		res := extractor.Extract(data)
		if len(res) != 2 {
			t.Fatalf("Expected 2 files extracted, got %d", len(res))
		}

		sort.Slice(res, func(i, j int) bool {
			return res[i].Path < res[j].Path
		})

		if res[0].Path != "src/main.go" || res[0].Hashes["sha256"] != "1111abcd" {
			t.Errorf("Unexpected result for src/main.go: %+v", res[0])
		}
		if res[1].Path != "src/util.go" || res[1].Hashes["sha1"] != "2222efgh" {
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

	t.Run("No opened files", func(t *testing.T) {
		data := map[string]interface{}{
			"processes": []interface{}{
				map[string]interface{}{
					"other": "data",
				},
			},
		}
		res := extractor.Extract(data)
		if len(res) != 0 {
			t.Errorf("Expected 0 files extracted, got %d", len(res))
		}
	})
}
