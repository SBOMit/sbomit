package resolver

import (
	"sort"
	"strings"
	"testing"
)

// Paths follow the shapes observed in results/rust/hexyl: CARGO_HOME at a
// custom root, the sparse-registry index beside the cache and src trees.
const (
	rustCargoHome = "/home/jake/cargocache/hexyl"
	rustRegistry  = rustCargoHome + "/registry"
	rustIndexDir  = "index.crates.io-1949cf8c6b5b557f"
)

func purls(packages []PackageInfo) []string {
	out := make([]string, 0, len(packages))
	for _, p := range packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

func TestRustResolverPrefersCrateArtifactAsEvidence(t *testing.T) {
	r := NewRustResolver()

	packages, _ := r.Resolve([]FileInfo{
		{
			Path:    rustRegistry + "/cache/" + rustIndexDir + "/anstream-0.6.17.crate",
			Digests: []Digest{{Algorithm: "sha256", Value: "aaa"}},
		},
		{Path: rustRegistry + "/src/" + rustIndexDir + "/anstream-0.6.17/src/lib.rs"},
		{Path: rustRegistry + "/src/" + rustIndexDir + "/anstream-0.6.17/Cargo.toml"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d: %v", len(packages), purls(packages))
	}
	if got := packages[0].PURL; got != "pkg:cargo/anstream@0.6.17" {
		t.Fatalf("unexpected PURL: %s", got)
	}

	// The .crate is what crates.io publishes, so it outranks Cargo.toml and
	// ordinary sources as the cited evidence.
	want := rustRegistry + "/cache/" + rustIndexDir + "/anstream-0.6.17.crate"
	if len(packages[0].Locations) != 1 || packages[0].Locations[0] != want {
		t.Fatalf("expected the .crate to be cited, got %v", packages[0].Locations)
	}
}

// Two versions of one crate are two packages.
func TestRustResolverKeepsBothVersionsOfACrate(t *testing.T) {
	r := NewRustResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: rustRegistry + "/src/" + rustIndexDir + "/bitflags-1.3.2/src/lib.rs"},
		{Path: rustRegistry + "/src/" + rustIndexDir + "/bitflags-2.6.0/src/lib.rs"},
	})

	got := purls(packages)
	want := []string{"pkg:cargo/bitflags@1.3.2", "pkg:cargo/bitflags@2.6.0"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected both versions, got %v", got)
	}
}

// The result must not depend on input order. The crates share a name, the
// case where name-only keying went wrong.
func TestRustResolverResultIsIndependentOfInputOrder(t *testing.T) {
	files := []FileInfo{
		{Path: rustRegistry + "/src/" + rustIndexDir + "/bitflags-1.3.2/src/lib.rs"},
		{Path: rustRegistry + "/src/" + rustIndexDir + "/bitflags-2.6.0/src/lib.rs"},
		{Path: rustRegistry + "/src/" + rustIndexDir + "/libc-0.2.161/src/lib.rs"},
	}
	reversed := []FileInfo{files[2], files[1], files[0]}

	forward, _ := NewRustResolver().Resolve(files)
	backward, _ := NewRustResolver().Resolve(reversed)

	if len(forward) != 3 {
		t.Fatalf("expected three packages, got %d: %v", len(forward), purls(forward))
	}
	if len(forward) != len(backward) {
		t.Fatalf("package count depends on input order: %d vs %d", len(forward), len(backward))
	}
	for i := range forward {
		if forward[i].PURL != backward[i].PURL {
			t.Fatalf("order depends on input order:\n  forward:  %v\n  backward: %v",
				purls(forward), purls(backward))
		}
	}
}

// The index directory (index.crates.io-<hash>) is not a crate.
func TestRustResolverIgnoresRegistryIndex(t *testing.T) {
	r := NewRustResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: rustRegistry + "/index/" + rustIndexDir + "/config.json"},
		{Path: rustRegistry + "/index/" + rustIndexDir + "/.cache/an/yh/anyhow"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages from the registry index, got %v", purls(packages))
	}
	if len(remaining) != 2 {
		t.Fatalf("index files should flow on unclaimed, got %d of 2", len(remaining))
	}
}

// Filenames shaped like <name>-<version> are not crate directories.
func TestRustResolverDoesNotTreatFilenamesAsCrateDirs(t *testing.T) {
	r := NewRustResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: rustRegistry + "/src/" + rustIndexDir + "/utf8parse-0.2.2/tests/UTF-8-demo.txt"},
		{Path: rustRegistry + "/src/" + rustIndexDir + "/utf8parse-0.2.2/src/lib.rs"},
	})

	got := purls(packages)
	if len(got) != 1 || got[0] != "pkg:cargo/utf8parse@0.2.2" {
		t.Fatalf("expected only utf8parse, got %v", got)
	}
}

func TestRustResolverPassesNonRustPathsThrough(t *testing.T) {
	r := NewRustResolver()

	_, remaining := r.Resolve([]FileInfo{
		{Path: "/etc/ld.so.cache"},
		{Path: "/home/jake/projects/hexyl/src/main.rs"},
	})

	if len(remaining) != 2 {
		t.Fatalf("expected both non-Rust paths to flow on, got %d", len(remaining))
	}
}

// The .crate is what crates.io publishes, so its digest is a package checksum
// a consumer can verify against the registry.
func TestRustResolverTakesPackageDigestFromCrateArtifact(t *testing.T) {
	r := NewRustResolver()

	packages, _ := r.Resolve([]FileInfo{
		{
			Path:    rustRegistry + "/cache/" + rustIndexDir + "/anstream-0.6.17.crate",
			Digests: []Digest{{Algorithm: "sha256", Value: "archive-digest"}},
		},
		{
			Path:    rustRegistry + "/src/" + rustIndexDir + "/anstream-0.6.17/src/lib.rs",
			Digests: []Digest{{Algorithm: "sha256", Value: "member-digest"}},
		},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if got := artifactDigest(packages[0], "sha256"); got != "archive-digest" {
		t.Fatalf("expected the artifact digest, got %q", got)
	}
}

// A crate seen only as extracted source has no artifact.
func TestRustResolverLeavesDigestEmptyWithoutTheArtifact(t *testing.T) {
	r := NewRustResolver()

	packages, _ := r.Resolve([]FileInfo{
		{
			Path:    rustRegistry + "/src/" + rustIndexDir + "/anstream-0.6.17/src/lib.rs",
			Digests: []Digest{{Algorithm: "sha256", Value: "member-digest"}},
		},
		{
			Path:    rustRegistry + "/src/" + rustIndexDir + "/anstream-0.6.17/Cargo.toml",
			Digests: []Digest{{Algorithm: "sha256", Value: "manifest-digest"}},
		},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].Artifact != nil {
		t.Fatalf("expected no package digest, got %v", packages[0].Artifact)
	}
}

// A crate renamed in Cargo.toml (itoa_old = { package = "itoa" }) at another
// version is a separate package owning only its own files.
func TestRustResolverSeparatesARenamedDependencyAtAnotherVersion(t *testing.T) {
	src := rustRegistry + "/src/" + rustIndexDir
	cache := rustRegistry + "/cache/" + rustIndexDir

	result := NewResolverChain().ResolveAll([]FileInfo{
		{Path: cache + "/itoa-1.0.11.crate"},
		{Path: src + "/itoa-1.0.11/src/lib.rs"},
		{Path: cache + "/itoa-0.4.8.crate"},
		{Path: src + "/itoa-0.4.8/src/lib.rs"},
	})

	got := purls(result.Packages)
	want := []string{"pkg:cargo/itoa@0.4.8", "pkg:cargo/itoa@1.0.11"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected both versions, got %v", got)
	}

	for _, owned := range result.Owned {
		version := strings.TrimPrefix(owned.OwnerPURL, "pkg:cargo/itoa@")
		if !strings.Contains(owned.Path, "/itoa-"+version) {
			t.Errorf("%s owns %s, which belongs to the other version", owned.OwnerPURL, owned.Path)
		}
	}
	if len(result.Owned) != 4 {
		t.Fatalf("expected all four files owned, got %d: %+v", len(result.Owned), result.Owned)
	}
}

// Build output identifies no crate, but it is still what the build did: it
// must reach the result rather than being dropped inside the resolver.
func TestRustResolverHandsOnBuildOutput(t *testing.T) {
	out := "/home/jake/projects/rust/hexyl/target/release/deps/hexyl-20a0c7a42e5a26ee.d"
	_, remaining := NewRustResolver().Resolve([]FileInfo{{Path: out}})

	if len(remaining) != 1 || remaining[0].Path != out {
		t.Fatalf("expected the build output to flow on, got %v", remaining)
	}
}
