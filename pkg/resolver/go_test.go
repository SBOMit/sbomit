package resolver

import (
	"strings"
	"testing"
)

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

	// /repo/main.go, plus the .ziphash: it belongs to the module but is not
	// what evidenced it, so it flows on for ownership attribution.
	if len(remaining) != 2 {
		t.Fatalf("expected two remaining files, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}

	pkg := packages[0]
	if pkg.PURL != "pkg:golang/github.com/BurntSushi/toml@v1.6.0" {
		t.Fatalf("unexpected PURL: %s", pkg.PURL)
	}

	// The .mod declares the module, so it outranks the .ziphash as evidence.
	wantLoc := "/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.6.0.mod"
	if len(pkg.Locations) != 1 || pkg.Locations[0] != wantLoc {
		t.Fatalf("unexpected locations: %v", pkg.Locations)
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

	// One path is cited as evidence; the other two stay for attribution.
	if len(remaining) != 2 {
		t.Fatalf("expected two remaining files, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].PURL != "pkg:golang/github.com/pkg/errors@v0.9.1" {
		t.Fatalf("unexpected PURL: %s", packages[0].PURL)
	}

	// .info and .mod both rank as module metadata, above the source file. The
	// tie breaks on the smaller path, which keeps the citation stable.
	wantLoc := "/home/user/go/pkg/mod/cache/download/github.com/pkg/errors/@v/v0.9.1.info"
	if len(packages[0].Locations) != 1 || packages[0].Locations[0] != wantLoc {
		t.Fatalf("unexpected locations: %v", packages[0].Locations)
	}
}

// The chain, unlike a bare resolver, attributes non-evidence files to the
// package that owns them instead of reporting them as loose files.
func TestResolverChainAttributesOwnedFiles(t *testing.T) {
	result := NewResolverChain().ResolveAll([]FileInfo{
		{Path: "/usr/lib/python3.11/site-packages/werkzeug-3.0.1.dist-info/METADATA"},
		{Path: "/usr/lib/python3.11/site-packages/werkzeug/routing/rules.py"},
		{Path: "/etc/ld.so.cache"},
	})

	if len(result.Packages) != 1 {
		t.Fatalf("expected one package, got %d", len(result.Packages))
	}

	pkg := result.Packages[0]
	if pkg.PURL != "pkg:pypi/werkzeug@3.0.1" {
		t.Fatalf("unexpected PURL: %s", pkg.PURL)
	}
	if len(pkg.Locations) != 1 || !strings.HasSuffix(pkg.Locations[0], "/METADATA") {
		t.Fatalf("expected METADATA as evidence, got %v", pkg.Locations)
	}

	// Both the evidence path and the member file are owned by werkzeug.
	if len(result.Owned) != 2 {
		t.Fatalf("expected two owned files, got %d: %+v", len(result.Owned), result.Owned)
	}
	for _, o := range result.Owned {
		if o.OwnerPURL != pkg.PURL {
			t.Errorf("file %q attributed to %q, want %q", o.Path, o.OwnerPURL, pkg.PURL)
		}
	}

	// Only the file no package claims is left over.
	if len(result.Files) != 1 || result.Files[0].Path != "/etc/ld.so.cache" {
		t.Fatalf("unexpected unowned files: %+v", result.Files)
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
