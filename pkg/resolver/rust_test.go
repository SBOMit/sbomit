package resolver

import (
	"testing"
)

func TestNormalizeRustCrateName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{" Serde ", "serde"},
		{"TOKIO", "tokio"},
		{"serde_json", "serde_json"},
	}

	for _, tt := range tests {
		got := NormalizeRustCrateName(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeRustCrateName(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestRustResolverResolvesCargoRegistryPaths(t *testing.T) {
	r := NewRustResolver()

	files := []FileInfo{
		{Path: "/root/.cargo/registry/cache/index.crates.io-6f17d22bba15001f/serde-1.0.197.crate"},
		{Path: "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.36.0/src/lib.rs"},
		{Path: "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.36.0/Cargo.toml"},
		{Path: "/workspace/src/main.rs"},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 2 {
		t.Fatalf("expected 2 resolved crates, got %d", len(packages))
	}

	pkgsByPURL := make(map[string]PackageInfo)
	for _, p := range packages {
		pkgsByPURL[p.PURL] = p
	}

	serdePkg, ok := pkgsByPURL["pkg:cargo/serde@1.0.197"]
	if !ok || serdePkg.Name != "serde" || serdePkg.Version != "1.0.197" || serdePkg.Ecosystem != "cargo" {
		t.Errorf("unexpected serde package details: %+v", serdePkg)
	}

	tokioPkg, ok := pkgsByPURL["pkg:cargo/tokio@1.36.0"]
	if !ok || tokioPkg.Name != "tokio" || tokioPkg.Version != "1.36.0" || tokioPkg.Ecosystem != "cargo" {
		t.Errorf("unexpected tokio package details: %+v", tokioPkg)
	}

	// Non-Rust files should remain
	foundMain := false
	for _, rem := range remaining {
		if rem.Path == "/workspace/src/main.rs" {
			foundMain = true
		}
	}
	if !foundMain {
		t.Errorf("expected /workspace/src/main.rs in remaining files")
	}
}

func TestRustResolverFiltersOwnedCompiledArtifacts(t *testing.T) {
	r := NewRustResolver()

	files := []FileInfo{
		{Path: "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/syn-2.0.58/src/lib.rs"},
		{Path: "/target/release/deps/syn-0123456789abcdef.rlib"},
		{Path: "/target/release/deps/syn-0123456789abcdef.rmeta"},
		{Path: "/target/debug/build/custom-tool"},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 1 || packages[0].Name != "syn" {
		t.Fatalf("expected syn package resolved, got %+v", packages)
	}

	for _, rem := range remaining {
		if rem.Path == "/target/release/deps/syn-0123456789abcdef.rlib" {
			t.Errorf("compiled artifact owned by syn should not remain: %s", rem.Path)
		}
	}
}

func TestRustPackageFilterMatches(t *testing.T) {
	r := NewRustResolver()

	packages := []PackageInfo{
		{Name: "serde", Version: "1.0.197", Ecosystem: "cargo"},
	}

	filters := r.CreateFileFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/root/.cargo/registry/cache/index.crates.io/serde-1.0.197.crate", true},
		{"/root/.cargo/registry/src/index.crates.io/serde-1.0.197/src/lib.rs", true},
		{"/root/.cargo/registry/src/index.crates.io/tokio-1.36.0/src/lib.rs", false},
		{"/workspace/serde.rs", false},
	}

	for _, tt := range tests {
		matched := filters[0].Matches(tt.path)
		if matched != tt.expected {
			t.Errorf("filter match for %q = %v, expected %v", tt.path, matched, tt.expected)
		}
	}
}
