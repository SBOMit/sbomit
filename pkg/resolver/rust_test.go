package resolver

import (
	"testing"
)

func TestRustResolverName(t *testing.T) {
	r := NewRustResolver()
	if r.Name() != "rust" {
		t.Errorf("Expected name 'rust', got '%s'", r.Name())
	}
}

func TestNormalizeRustCrateName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Serde", "serde"},
		{"  tokio  ", "tokio"},
		{"Rand-Core", "rand-core"},
	}

	for _, test := range tests {
		actual := NormalizeRustCrateName(test.input)
		if actual != test.expected {
			t.Errorf("Expected '%s', got '%s'", test.expected, actual)
		}
	}
}

func TestRustResolverResolve(t *testing.T) {
	r := NewRustResolver()

	files := []FileInfo{
		{Path: "home/user/.cargo/registry/cache/github.com-1ecc6299db9ec823/serde-1.0.126.crate"},
		{Path: "home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-1.12.0/src/lib.rs"},
		{Path: "src/main.rs"},
		{Path: "project/target/release/libtokio.rlib"}, // Should be ignored or handled as compiled artifact
	}

	pkgs, remaining := r.Resolve(files)

	if len(pkgs) != 2 {
		t.Errorf("Expected 2 packages resolved, got %d", len(pkgs))
	}
	if len(remaining) != 3 {
		t.Errorf("Expected 3 files remaining, got %d", len(remaining))
	}

	foundSerde := false
	for _, p := range pkgs {
		if p.Name == "serde" {
			foundSerde = true
			if p.Version != "1.0.126" {
				t.Errorf("Expected serde version '1.0.126', got '%s'", p.Version)
			}
		}
	}
	if !foundSerde {
		t.Errorf("Serde package not found in resolved packages")
	}
}

func TestRustPackageFilterMatches(t *testing.T) {
	filter := &rustPackageFilter{
		packageName: "serde",
		version:     "1.0.126",
	}

	if !filter.Matches("home/user/.cargo/registry/cache/github.com-1ecc6299db9ec823/serde-1.0.126.crate") {
		t.Errorf("Expected match for serde crate")
	}
	if !filter.Matches("home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.126/src/lib.rs") {
		t.Errorf("Expected match for serde src")
	}
	if filter.Matches("home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-1.12.0/src/lib.rs") {
		t.Errorf("Did not expect match for tokio")
	}
	if filter.Matches("src/main.rs") {
		t.Errorf("Did not expect match for src file")
	}
}
