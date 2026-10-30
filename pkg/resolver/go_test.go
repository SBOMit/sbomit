package resolver

import (
	"strings"
	"testing"
)

func TestGoResolverResolvesModuleCacheDownloadFiles(t *testing.T) {
	r := NewGoResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{
			Path:    "/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.6.0.mod",
			Digests: []Digest{{Algorithm: "sha256", Value: "abc123"}},
		},
		{
			Path:    "/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.6.0.ziphash",
			Digests: []Digest{{Algorithm: "sha256", Value: "def456"}},
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
	if pkg.Artifact != nil {
		t.Fatalf("cache file hashes should not be promoted to package hashes: %#v", pkg.Artifact)
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

// cache/download/<module>/@v/list must not be read as a module at version "v".
func TestGoResolverIgnoresNonArtifactCachePaths(t *testing.T) {
	r := NewGoResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/lib/pq/@v/v1.11.1.zip"},
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/lib/pq/@v/list"},
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/lib/pq/@v/lock"},
		{Path: "/home/user/go/pkg/mod/cache/download/sumdb/sum.golang.org/lookup/github.com/lib/pq@v1.11.1"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d: %v", len(packages), goPURLs(packages))
	}
	if got := packages[0].PURL; got != "pkg:golang/github.com/lib/pq@v1.11.1" {
		t.Fatalf("unexpected PURL: %s", got)
	}

	// list, lock and the sumdb entry identify no module, so they flow on.
	if len(remaining) != 3 {
		t.Fatalf("expected three remaining files, got %d", len(remaining))
	}
}

func TestGoResolverResolvesExtractedModuleDir(t *testing.T) {
	r := NewGoResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: "/home/user/go/pkg/mod/github.com/!i!g!l!o!u-!e!u/go-wildcard@v1.0.3/wildcard.go"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	// Go escapes uppercase letters in module paths as !<lowercase>.
	if got := packages[0].PURL; got != "pkg:golang/github.com/IGLOU-EU/go-wildcard@v1.0.3" {
		t.Fatalf("unexpected PURL: %s", got)
	}
}

func goPURLs(packages []PackageInfo) []string {
	out := make([]string, 0, len(packages))
	for _, p := range packages {
		out = append(out, p.PURL)
	}
	return out
}

// The module zip is the artifact; an extracted copy has none.
func TestGoResolverTakesPackageDigestFromModuleZip(t *testing.T) {
	const cache = "/home/user/go/pkg/mod/cache/download/github.com/lib/pq/@v"

	fromZip, _ := NewGoResolver().Resolve([]FileInfo{
		{Path: cache + "/v1.11.1.zip", Digests: []Digest{{Algorithm: "sha256", Value: "archive-digest"}}},
		{Path: cache + "/v1.11.1.mod", Digests: []Digest{{Algorithm: "sha256", Value: "mod-digest"}}},
	})
	if len(fromZip) != 1 {
		t.Fatalf("expected one package, got %d", len(fromZip))
	}
	if got := artifactDigest(fromZip[0], "sha256"); got != "archive-digest" {
		t.Fatalf("expected the zip digest, got %q", got)
	}

	fromExtracted, _ := NewGoResolver().Resolve([]FileInfo{
		{
			Path:    "/home/user/go/pkg/mod/github.com/lib/pq@v1.11.1/conn.go",
			Digests: []Digest{{Algorithm: "sha256", Value: "member-digest"}},
		},
	})
	if len(fromExtracted) != 1 {
		t.Fatalf("expected one package, got %d", len(fromExtracted))
	}
	if fromExtracted[0].Artifact != nil {
		t.Fatalf("expected no package digest, got %v", fromExtracted[0].Artifact)
	}
}
