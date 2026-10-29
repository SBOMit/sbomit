package resolver

import (
	"sort"
	"testing"
)

// Paths follow the shapes observed in results/js/pnpm-action-setup.
const pnpmProject = "/home/jake/projects/js/pnpm-action-setup"

func npmPURLs(packages []PackageInfo) []string {
	out := make([]string, 0, len(packages))
	for _, p := range packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

func TestJavaScriptResolverResolvesPnpmStore(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions/cache/package.json"},
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions/cache/lib/cache.js"},
		{Path: pnpmProject + "/node_modules/.pnpm/semver@7.8.5/node_modules/semver/package.json"},
	})

	got := npmPURLs(packages)
	want := []string{"pkg:npm/@actions/cache@4.1.0", "pkg:npm/semver@7.8.5"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}

	// package.json declares the name and version, so it outranks lib/cache.js.
	for _, p := range packages {
		if p.Name != "@actions/cache" {
			continue
		}
		want := pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions/cache/package.json"
		if len(p.Locations) != 1 || p.Locations[0] != want {
			t.Fatalf("expected package.json to be cited, got %v", p.Locations)
		}
	}
}

// A dependency linked into a pnpm store directory must not take that
// directory's version.
func TestJavaScriptResolverDoesNotPairDependencyWithOwnersVersion(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions/cache/package.json"},
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions/core/lib/core.js"},
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/semver/index.js"},
	})

	got := npmPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:npm/@actions/cache@4.1.0" {
		t.Fatalf("expected only @actions/cache@4.1.0, got %v", got)
	}

	// The dependency symlinks are not identity, but they are still attested
	// paths, so they flow on for ownership attribution.
	if len(remaining) != 2 {
		t.Fatalf("expected the two dependency paths to flow on, got %d", len(remaining))
	}
}

// A bare scope directory (".../@actions") is not a package.
func TestJavaScriptResolverIgnoresBareScopeDirectory(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions"},
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages from directory entries, got %v", npmPURLs(packages))
	}
	if len(remaining) != 2 {
		t.Fatalf("expected both directory entries to flow on, got %d", len(remaining))
	}
}

// pnpm keys a store directory by its peer-dependency set, which is not part of
// the package's version.
func TestJavaScriptResolverStripsPeerDependencySuffix(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: pnpmProject + "/node_modules/.pnpm/debug@4.4.3(supports-color@8.1.1)/node_modules/debug/package.json"},
	})

	got := npmPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:npm/debug@4.4.3" {
		t.Fatalf("expected pkg:npm/debug@4.4.3, got %v", got)
	}
}

// npm and yarn-with-node-modules install flat, and those paths carry no
// version anywhere. Deriving a package from it would mean inventing one.
func TestJavaScriptResolverIgnoresFlatNodeModules(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: pnpmProject + "/node_modules/@aashutoshrathi/word-wrap/index.js"},
		{Path: pnpmProject + "/node_modules/semver/index.js"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages from a flat tree, got %v", npmPURLs(packages))
	}
	if len(remaining) != 2 {
		t.Fatalf("expected both flat paths to flow on, got %d", len(remaining))
	}
}

func TestJavaScriptResolverAttributesStoreFilesToTheirPackage(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions/cache/package.json"},
	})

	filters := r.OwnershipFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected one ownership filter, got %d", len(filters))
	}

	owned := pnpmProject + "/node_modules/.pnpm/@actions+cache@4.1.0/node_modules/@actions/cache/lib/cache.js"
	if !filters[0].Matcher.Matches(NewPath(owned)) {
		t.Fatalf("expected the package to own %s", owned)
	}

	foreign := pnpmProject + "/node_modules/.pnpm/semver@7.8.5/node_modules/semver/index.js"
	if filters[0].Matcher.Matches(NewPath(foreign)) {
		t.Fatalf("did not expect @actions/cache to own %s", foreign)
	}
}

const yarnProject = "/home/jake/projects/js/docker-login-action"

// The yarn cache zip identifies the package but is not its npm artifact.
func TestJavaScriptResolverResolvesYarnBerryCache(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{
			Path:    yarnProject + "/.yarn/cache/semver-npm-7.8.5-687bb8a5bc-b2b3d219d3.zip",
			Digests: []Digest{{Algorithm: "sha256", Value: "archive-digest"}},
		},
	})

	got := npmPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:npm/semver@7.8.5" {
		t.Fatalf("expected pkg:npm/semver@7.8.5, got %v", got)
	}

	if packages[0].PkgMgr != "yarn" {
		t.Fatalf("expected manager yarn, got %q", packages[0].PkgMgr)
	}
	if packages[0].Artifact != nil {
		t.Fatalf("a yarn cache zip is not the npm artifact, got %+v", packages[0].Artifact)
	}
}

// Yarn's flattened scope is resolved against names seen in node_modules.
func TestJavaScriptResolverRecoversYarnScopeFromNodeModules(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: yarnProject + "/.yarn/cache/@aashutoshrathi-word-wrap-npm-1.2.6-5b1d95e487-6eebd12a5c.zip"},
		{Path: yarnProject + "/node_modules/@aashutoshrathi/word-wrap/index.js"},
	})

	got := npmPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:npm/@aashutoshrathi/word-wrap@1.2.6" {
		t.Fatalf("expected the scope to be recovered, got %v", got)
	}
}

// An unconfirmed flattened scope is kept verbatim, not guessed.
func TestJavaScriptResolverDoesNotGuessYarnScope(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: yarnProject + "/.yarn/cache/@docker-cli-foo-npm-1.0.0-5b1d95e487-6eebd12a5c.zip"},
	})

	got := npmPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:npm/@docker-cli-foo@1.0.0" {
		t.Fatalf("expected the flattened name kept verbatim, got %v", got)
	}
}

// A flat node_modules path is attributed only if one version was resolved.
func TestJavaScriptResolverAttributesFlatTreeOnlyWhenUnambiguous(t *testing.T) {
	r := NewJavaScriptResolver()

	oneVersion, _ := r.Resolve([]FileInfo{
		{Path: yarnProject + "/.yarn/cache/semver-npm-7.8.5-687bb8a5bc-b2b3d219d3.zip"},
	})
	filters := r.OwnershipFilters(oneVersion)
	flat := yarnProject + "/node_modules/semver/index.js"
	if !filters[0].Matcher.Matches(NewPath(flat)) {
		t.Fatalf("a single resolved version should own %s", flat)
	}

	twoVersions, _ := r.Resolve([]FileInfo{
		{Path: yarnProject + "/.yarn/cache/semver-npm-7.8.5-687bb8a5bc-b2b3d219d3.zip"},
		{Path: yarnProject + "/.yarn/cache/semver-npm-6.3.1-687bb8a5bc-b2b3d219d3.zip"},
	})
	for _, f := range r.OwnershipFilters(twoVersions) {
		if f.Matcher.Matches(NewPath(flat)) {
			t.Fatalf("%s owns %s, but which version sits there is unknowable", f.PURL, flat)
		}
	}
}
