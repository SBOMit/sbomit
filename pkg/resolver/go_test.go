package resolver

import "testing"

func TestGoResolverResolvesModuleCacheDownloadFiles(t *testing.T) {
	r := NewGoResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{
			Path: "/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.6.0.mod",
			Hashes: map[string]string{
				"sha256": "abc123",
			},
		},
		{
			Path: "/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.6.0.ziphash",
			Hashes: map[string]string{
				"sha256": "def456",
			},
		},
		{Path: "/repo/main.go"},
	})

	if len(remaining) != 1 {
		t.Fatalf("expected one remaining file, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}

	pkg := packages[0]
	if pkg.PURL != "pkg:golang/github.com/BurntSushi/toml@v1.6.0" {
		t.Fatalf("unexpected PURL: %s", pkg.PURL)
	}
	if pkg.Name != "github.com/BurntSushi/toml" {
		t.Fatalf("unexpected package name: %s", pkg.Name)
	}
	if len(pkg.Hashes) != 0 {
		t.Fatalf("cache file hashes should not be promoted to package hashes: %#v", pkg.Hashes)
	}
}

func TestGoResolverAggregatesModuleCacheAndSourcePaths(t *testing.T) {
	r := NewGoResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go"},
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/pkg/errors/@v/v0.9.1.mod"},
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/pkg/errors/@v/v0.9.1.info"},
	})

	if len(remaining) != 0 {
		t.Fatalf("expected no remaining files, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].PURL != "pkg:golang/github.com/pkg/errors@v0.9.1" {
		t.Fatalf("unexpected PURL: %s", packages[0].PURL)
	}
}

func TestGoResolverEscapesPURLVersion(t *testing.T) {
	r := NewGoResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: "/home/user/go/pkg/mod/github.com/peterbourgon/diskv@v2.0.1+incompatible/diskv.go"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].PURL != "pkg:golang/github.com/peterbourgon/diskv@v2.0.1%2Bincompatible" {
		t.Fatalf("unexpected PURL: %s", packages[0].PURL)
	}
}
