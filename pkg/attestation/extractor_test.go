package attestation

import (
	"sort"
	"testing"
)

func TestMaterialExtractor(t *testing.T) {
	e := NewMaterialExtractor()
	if e.Name() != "material" {
		t.Fatalf("expected extractor name 'material', got %q", e.Name())
	}

	data := map[string]interface{}{
		"materials": map[string]interface{}{
			"src/main.go": map[string]interface{}{
				"sha256": "abcdef123456",
				"sha1":   "123456abcdef",
			},
			"go.mod": map[string]interface{}{
				"gitoid": "blob:40digits",
			},
			"empty_hashes.txt": map[string]interface{}{},
		},
	}

	files := e.Extract(data)
	if len(files) != 2 {
		t.Fatalf("expected 2 files with valid hashes extracted, got %d", len(files))
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	if files[0].Path != "go.mod" || files[0].Hashes["gitoid"] != "blob:40digits" {
		t.Errorf("unexpected file entry: %+v", files[0])
	}
	if files[1].Path != "src/main.go" || files[1].Hashes["sha256"] != "abcdef123456" {
		t.Errorf("unexpected file entry: %+v", files[1])
	}
}

func TestProductExtractor(t *testing.T) {
	e := NewProductExtractor()
	if e.Name() != "product" {
		t.Fatalf("expected extractor name 'product', got %q", e.Name())
	}

	data := map[string]interface{}{
		"products": map[string]interface{}{
			"bin/app": map[string]interface{}{
				"sha256": "998877665544",
			},
		},
	}

	files := e.Extract(data)
	if len(files) != 1 {
		t.Fatalf("expected 1 product file, got %d", len(files))
	}
	if files[0].Path != "bin/app" || files[0].Hashes["sha256"] != "998877665544" {
		t.Fatalf("unexpected product extracted: %+v", files[0])
	}
}

func TestCommandRunExtractorProcessDeduplication(t *testing.T) {
	e := NewCommandRunExtractor()
	if e.Name() != "command-run" {
		t.Fatalf("expected extractor name 'command-run', got %q", e.Name())
	}

	data := map[string]interface{}{
		"processes": []interface{}{
			map[string]interface{}{
				"openedfiles": map[string]interface{}{
					"/usr/lib/libc.so": map[string]interface{}{
						"sha256": "libc-hash-1",
					},
					"/app/src/parser.go": map[string]interface{}{
						"sha256": "parser-hash",
					},
				},
			},
			map[string]interface{}{
				"openedfiles": map[string]interface{}{
					"/usr/lib/libc.so": map[string]interface{}{
						"sha256": "libc-hash-1",
					},
					"/app/src/compiler.go": map[string]interface{}{
						"sha256": "compiler-hash",
					},
				},
			},
		},
	}

	files := e.Extract(data)
	if len(files) != 3 {
		t.Fatalf("expected 3 deduplicated files across processes, got %d", len(files))
	}

	paths := make(map[string]string)
	for _, f := range files {
		paths[f.Path] = f.Hashes["sha256"]
	}

	expected := []string{"/usr/lib/libc.so", "/app/src/parser.go", "/app/src/compiler.go"}
	for _, p := range expected {
		if _, ok := paths[p]; !ok {
			t.Errorf("expected path %q to be present in extracted files", p)
		}
	}
}

func TestExtractorChainExtractAllAndSupportedTypes(t *testing.T) {
	chain := NewExtractorChain()
	supported := chain.SupportedTypes()
	sort.Strings(supported)

	expectedTypes := []string{"command-run", "material", "product"}
	if len(supported) != len(expectedTypes) {
		t.Fatalf("expected %d supported types, got %d", len(expectedTypes), len(supported))
	}

	for i, exp := range expectedTypes {
		if supported[i] != exp {
			t.Errorf("expected supported type %q, got %q", exp, supported[i])
		}
	}

	attestations := []TypedAttestation{
		{
			Type: "material",
			Data: map[string]interface{}{
				"materials": map[string]interface{}{
					"shared/file.go": map[string]interface{}{"sha256": "hash-from-material"},
				},
			},
		},
		{
			Type: "product",
			Data: map[string]interface{}{
				"products": map[string]interface{}{
					"shared/file.go": map[string]interface{}{"sha256": "hash-from-product"},
					"output/binary":  map[string]interface{}{"sha256": "bin-hash"},
				},
			},
		},
		{
			Type: "unknown-type",
			Data: map[string]interface{}{},
		},
	}

	extracted := chain.ExtractAll(attestations, nil)
	if len(extracted) != 2 {
		t.Fatalf("expected 2 files with shared path deduplicated, got %d", len(extracted))
	}

	if extracted[0].Path != "shared/file.go" || extracted[0].Hashes["sha256"] != "hash-from-material" {
		t.Errorf("expected first seen path entry preserved: %+v", extracted[0])
	}
	if extracted[1].Path != "output/binary" || extracted[1].Hashes["sha256"] != "bin-hash" {
		t.Errorf("expected second distinct path: %+v", extracted[1])
	}

	materialOnly := chain.ExtractAll(attestations, []string{"material"})
	if len(materialOnly) != 1 || materialOnly[0].Path != "shared/file.go" {
		t.Fatalf("expected only material files extracted when filtered: %+v", materialOnly)
	}
}
