package resolver

import (
	"testing"
)

func TestRustResolver_DeterministicOrder(t *testing.T) {
	r := NewRustResolver()

	files := []FileInfo{
		{Path: "/registry/src/github.com/a/tokio-1.0.0/src/lib.rs"},
		{Path: "/registry/src/github.com/a/serde-1.0.0/src/lib.rs"},
	}

	pkgs, _ := r.Resolve(files)

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	if pkgs[0].Name != "serde" {
		t.Errorf("expected serde first, got %s", pkgs[0].Name)
	}

	if pkgs[1].Name != "tokio" {
		t.Errorf("expected tokio second, got %s", pkgs[1].Name)
	}
}

func TestRustResolver_StableOutput(t *testing.T) {
	r := NewRustResolver()

	files := []FileInfo{
		{Path: "/registry/src/github.com/a/zeta-1.0.0/src/lib.rs"},
		{Path: "/registry/src/github.com/a/alpha-1.0.0/src/lib.rs"},
	}

	pkgs1, _ := r.Resolve(files)
	pkgs2, _ := r.Resolve(files)

	if pkgs1[0].Name != pkgs2[0].Name {
		t.Errorf("output is not stable across runs")
	}
}
