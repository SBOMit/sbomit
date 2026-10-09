package attestation

import (
	"sort"
	"testing"
)

func TestProductExtractor(t *testing.T) {
	extractor := NewProductExtractor()

	if extractor.Name() != "product" {
		t.Errorf("Expected Name 'product', got %s", extractor.Name())
	}

	t.Run("Valid products map", func(t *testing.T) {
		data := map[string]interface{}{
			"products": map[string]interface{}{
				"bin/app": map[string]interface{}{
					"sha256": "1111abcd",
				},
				"dist/library.so": map[string]interface{}{
					"sha1": "2222efgh",
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

		if res[0].Path != "bin/app" || res[0].Hashes["sha256"] != "1111abcd" {
			t.Errorf("Unexpected result for bin/app: %+v", res[0])
		}
		if res[1].Path != "dist/library.so" || res[1].Hashes["sha1"] != "2222efgh" {
			t.Errorf("Unexpected result for dist/library.so: %+v", res[1])
		}
	})

	t.Run("Empty input", func(t *testing.T) {
		data := map[string]interface{}{}
		res := extractor.Extract(data)
		if len(res) != 0 {
			t.Errorf("Expected 0 files extracted from empty input, got %d", len(res))
		}
	})

	t.Run("Flat structure (legacy)", func(t *testing.T) {
		data := map[string]interface{}{
			"bin/legacy": map[string]interface{}{
				"sha256": "aaaa",
			},
			"command": "ignore_me",
		}

		res := extractor.Extract(data)
		if len(res) != 1 {
			t.Fatalf("Expected 1 file extracted, got %d", len(res))
		}
		if res[0].Path != "bin/legacy" || res[0].Hashes["sha256"] != "aaaa" {
			t.Errorf("Unexpected result: %+v", res[0])
		}
	})
}
