package attestation

import (
	"reflect"
	"testing"
)

type fakeExtractor struct {
	name     string
	out      []FileInfo
	called   int
	lastData map[string]interface{}
}

func (f *fakeExtractor) Name() string {
	return f.name
}

func (f *fakeExtractor) Extract(data map[string]interface{}) []FileInfo {
	f.called++
	f.lastData = data

	copied := make([]FileInfo, len(f.out))
	copy(copied, f.out)
	return copied
}

func TestNewExtractorChain_RegistersDefaultExtractors(t *testing.T) {
	chain := NewExtractorChain()

	for _, typ := range []string{"material", "command-run", "product"} {
		extractor, ok := chain.GetExtractor(typ)
		if !ok {
			t.Fatalf("expected extractor for type %q to be registered", typ)
		}
		if extractor == nil {
			t.Fatalf("expected non-nil extractor for type %q", typ)
		}
		if extractor.Name() != typ {
			t.Fatalf("expected extractor name %q, got %q", typ, extractor.Name())
		}
	}

	if _, ok := chain.GetExtractor("unknown"); ok {
		t.Fatalf("did not expect extractor for unknown type")
	}
}

func TestExtractorChain_SupportedTypes(t *testing.T) {
	chain := NewExtractorChain()
	got := chain.SupportedTypes()

	wantSet := map[string]struct{}{
		"material":    {},
		"command-run": {},
		"product":     {},
	}

	if len(got) != len(wantSet) {
		t.Fatalf("expected %d supported types, got %d (%v)", len(wantSet), len(got), got)
	}

	for _, typ := range got {
		if _, ok := wantSet[typ]; !ok {
			t.Fatalf("unexpected supported type %q", typ)
		}
		delete(wantSet, typ)
	}

	if len(wantSet) != 0 {
		t.Fatalf("missing supported types: %v", wantSet)
	}
}

func TestExtractorChain_RegisterExtractor(t *testing.T) {
	chain := &ExtractorChain{extractors: make(map[string]Extractor)}
	f := &fakeExtractor{name: "custom"}

	chain.RegisterExtractor(f)

	got, ok := chain.GetExtractor("custom")
	if !ok {
		t.Fatalf("expected custom extractor to be registered")
	}
	if got != f {
		t.Fatalf("expected the registered extractor instance to be returned")
	}
}

func TestExtractorChain_ExtractAll(t *testing.T) {
	tests := []struct {
		name        string
		attest      []TypedAttestation
		typeFilter  []string
		wantFiles   []FileInfo
		wantMatCall int
		wantProCall int
	}{
		{
			name: "deduplicates paths and preserves first seen file",
			attest: []TypedAttestation{
				{Type: "material", Data: map[string]interface{}{"source": "materials"}},
				{Type: "product", Data: map[string]interface{}{"source": "products"}},
				{Type: "unknown", Data: map[string]interface{}{"source": "ignored"}},
			},
			wantFiles: []FileInfo{
				{Path: "/a.txt", Hashes: map[string]string{"sha256": "a"}},
				{Path: "/shared.txt", Hashes: map[string]string{"sha256": "from-material"}},
				{Path: "/b.txt", Hashes: map[string]string{"sha256": "b"}},
			},
			wantMatCall: 1,
			wantProCall: 1,
		},
		{
			name: "applies type filter",
			attest: []TypedAttestation{
				{Type: "material", Data: map[string]interface{}{"source": "materials"}},
				{Type: "product", Data: map[string]interface{}{"source": "products"}},
			},
			typeFilter: []string{"product"},
			wantFiles: []FileInfo{
				{Path: "/shared.txt", Hashes: map[string]string{"sha256": "from-product"}},
				{Path: "/b.txt", Hashes: map[string]string{"sha256": "b"}},
			},
			wantMatCall: 0,
			wantProCall: 1,
		},
		{
			name: "no matching type filter returns no files",
			attest: []TypedAttestation{
				{Type: "material", Data: map[string]interface{}{"source": "materials"}},
				{Type: "product", Data: map[string]interface{}{"source": "products"}},
			},
			typeFilter:  []string{"command-run"},
			wantFiles:   nil,
			wantMatCall: 0,
			wantProCall: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := &fakeExtractor{
				name: "material",
				out: []FileInfo{
					{Path: "/a.txt", Hashes: map[string]string{"sha256": "a"}},
					{Path: "/shared.txt", Hashes: map[string]string{"sha256": "from-material"}},
				},
			}
			product := &fakeExtractor{
				name: "product",
				out: []FileInfo{
					{Path: "/shared.txt", Hashes: map[string]string{"sha256": "from-product"}},
					{Path: "/b.txt", Hashes: map[string]string{"sha256": "b"}},
				},
			}

			chain := &ExtractorChain{
				extractors: map[string]Extractor{
					"material": material,
					"product":  product,
				},
			}

			got := chain.ExtractAll(tt.attest, tt.typeFilter)

			if !reflect.DeepEqual(got, tt.wantFiles) {
				t.Fatalf("ExtractAll() mismatch\nwant: %#v\ngot:  %#v", tt.wantFiles, got)
			}

			if material.called != tt.wantMatCall {
				t.Fatalf("material extractor called %d times, want %d", material.called, tt.wantMatCall)
			}

			if product.called != tt.wantProCall {
				t.Fatalf("product extractor called %d times, want %d", product.called, tt.wantProCall)
			}
		})
	}
}
