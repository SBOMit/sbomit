package resolve

import (
	"os"
	"path/filepath"
	"testing"
	"github.com/sbomit/sbomit/pkg/attestation"
)

func TestResolveFromFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "sample-attestation.json"))
	if err != nil {
		t.Fatalf("failed to read test attestation: %v", err)
	}

	result, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Packages) == 0 {
		t.Fatal("expected at least one package to be resolved")
	}

	// Verify all packages have required fields
	for _, pkg := range result.Packages {
		if pkg.ID == "" {
			t.Errorf("package %q has empty ID", pkg.Name)
		}
		if pkg.Name == "" {
			t.Errorf("package with PURL %q has empty Name", pkg.PURL)
		}
		if pkg.Ecosystem == "" {
			t.Errorf("package %q has empty Ecosystem", pkg.Name)
		}
		if pkg.PURL == "" {
			t.Errorf("package %q has empty PURL", pkg.Name)
		}
		if pkg.FoundBy == "" {
			t.Errorf("package %q has empty FoundBy", pkg.Name)
		}
	}
}

func TestResolveOrjsonWitness(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "orjson_witness.json"))
	if err != nil {
		t.Fatalf("failed to read test attestation: %v", err)
	}

	result, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Packages) != 89 {
		t.Errorf("expected 89 packages, got %d", len(result.Packages))
	}
	if len(result.Files) != 625 {
		t.Errorf("expected 625 files, got %d", len(result.Files))
	}
}

func TestResolveAttestationsDirect(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "sample-attestation.json"))
	if err != nil {
		t.Fatalf("failed to read test attestation: %v", err)
	}

	attestations, err := attestation.ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("failed to parse witness data: %v", err)
	}

	resultFromBytes, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	resultFromParsed, err := ResolveAttestations(attestations, Options{})
	if err != nil {
		t.Fatalf("ResolveAttestations failed: %v", err)
	}

	if len(resultFromBytes.Packages) != len(resultFromParsed.Packages) {
		t.Errorf("package count mismatch: Resolve=%d vs ResolveAttestations=%d",
			len(resultFromBytes.Packages), len(resultFromParsed.Packages))
	}
	if len(resultFromBytes.Files) != len(resultFromParsed.Files) {
		t.Errorf("file count mismatch: Resolve=%d vs ResolveAttestations=%d",
			len(resultFromBytes.Files), len(resultFromParsed.Files))
	}
}

func BenchmarkResolve(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "sample-attestation.json"))
	if err != nil {
		b.Fatalf("failed to read test attestation: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Resolve(data, Options{})
		if err != nil {
			b.Fatalf("Resolve failed: %v", err)
		}
	}
}


func TestResolvePackageIDStability(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "sample-attestation.json"))
	if err != nil {
		t.Fatalf("failed to read test attestation: %v", err)
	}

	result1, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("first Resolve returned error: %v", err)
	}

	result2, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("second Resolve returned error: %v", err)
	}

	if len(result1.Packages) != len(result2.Packages) {
		t.Fatalf("package count mismatch: %d vs %d", len(result1.Packages), len(result2.Packages))
	}

	// Build PURL->ID map from second run for comparison.
	// Package ordering may differ across runs (Go map iteration), but ID
	// for the same PURL must be deterministic.
	idByPURL := make(map[string]string, len(result2.Packages))
	for _, p := range result2.Packages {
		idByPURL[p.PURL] = p.ID
	}

	for _, p1 := range result1.Packages {
		id2, ok := idByPURL[p1.PURL]
		if !ok {
			t.Errorf("package %q (PURL %s) missing from second run", p1.Name, p1.PURL)
			continue
		}
		if p1.ID != id2 {
			t.Errorf("package %q ID not stable: %q vs %q", p1.Name, p1.ID, id2)
		}
	}
}

func TestResolveWithExcludePaths(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "sample-attestation.json"))
	if err != nil {
		t.Fatalf("failed to read test attestation: %v", err)
	}

	// Resolve without excludes
	resultAll, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	// Resolve with a glob that excludes python site-packages
	resultExcluded, err := Resolve(data, Options{
		ExcludePaths: []string{"*site-packages*"},
	})
	if err != nil {
		t.Fatalf("Resolve with excludes returned error: %v", err)
	}

	// The excluded result should have <= packages than the full one
	if len(resultExcluded.Packages) > len(resultAll.Packages) {
		t.Errorf("excluding paths should not produce more packages: %d vs %d",
			len(resultExcluded.Packages), len(resultAll.Packages))
	}
}

func TestResolveEmptyInput(t *testing.T) {
	// Resolve with valid but empty attestation data should not error
	emptyStatement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://witness.testifysec.com/attestation-collection/v0.1","subject":[],"predicate":{"name":"empty","attestations":[]}}`)

	result, err := Resolve(emptyStatement, Options{})
	if err != nil {
		t.Fatalf("Resolve empty attestation returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for empty attestation")
	}
	if len(result.Packages) != 0 {
		t.Errorf("expected 0 packages for empty attestation, got %d", len(result.Packages))
	}
}

func TestUnownedFiles(t *testing.T) {
	r := &Result{
		Files: []File{
			{Path: "/a"},
			{Path: "/b"},
			{Path: "/c"},
		},
		Relationships: []Relationship{
			{Type: Contains, FromPackageID: "p1", ToPath: "/b"},
		},
	}

	unowned := r.UnownedFiles()
	if len(unowned) != 2 {
		t.Fatalf("expected 2 unowned files, got %d", len(unowned))
	}
	if unowned[0].Path != "/a" || unowned[1].Path != "/c" {
		t.Errorf("unexpected unowned files: %v", unowned)
	}
}

func TestPackageByID(t *testing.T) {
	r := &Result{
		Packages: []Package{
			{ID: "abc", Name: "foo"},
			{ID: "def", Name: "bar"},
		},
	}

	pkg, ok := r.PackageByID("def")
	if !ok {
		t.Fatal("expected to find package with ID def")
	}
	if pkg.Name != "bar" {
		t.Errorf("expected Name bar, got %s", pkg.Name)
	}

	_, ok = r.PackageByID("nonexistent")
	if ok {
		t.Fatal("expected not to find nonexistent package")
	}
}

func TestDigestsOfOrdering(t *testing.T) {
	m := map[string]string{
		"sha512": "ccc",
		"sha1":   "aaa",
		"sha256": "bbb",
	}

	digests := digestsOf(m)
	if len(digests) != 3 {
		t.Fatalf("expected 3 digests, got %d", len(digests))
	}
	if digests[0].Algorithm != "sha1" {
		t.Errorf("expected first algorithm sha1, got %s", digests[0].Algorithm)
	}
	if digests[1].Algorithm != "sha256" {
		t.Errorf("expected second algorithm sha256, got %s", digests[1].Algorithm)
	}
	if digests[2].Algorithm != "sha512" {
		t.Errorf("expected third algorithm sha512, got %s", digests[2].Algorithm)
	}
}

func TestDigestsOfNil(t *testing.T) {
	digests := digestsOf(nil)
	if digests != nil {
		t.Errorf("expected nil for nil map, got %v", digests)
	}
}
