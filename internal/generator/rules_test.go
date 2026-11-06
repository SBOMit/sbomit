package generator

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/sbomit/sbomit/pkg/resolve"
)

func selectedFromSample(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", name+".json"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	result, err := resolve.Resolve(data, resolve.Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var out []string
	for _, p := range applyRules(result).Packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

// Download-only packages are included only when npm fetched them.
func TestApplyRulesKeepsDownloadsOnlyWhereNoPathCouldShowThem(t *testing.T) {
	for _, tc := range []struct {
		sample string
		want   []string
		why    string
	}{
		{
			sample: "js-pnpm-action-setup",
			want:   []string{"pkg:npm/@actions/cache@4.1.0", "pkg:npm/@actions/core@1.11.1", "pkg:npm/@actions/exec@1.1.1"},
			why:    "pnpm's store is versioned, so @azure/core-paging, fetched and never installed, is dropped",
		},
		{
			sample: "js-docker-login-action",
			want:   []string{"pkg:npm/@aashutoshrathi/word-wrap@1.2.6", "pkg:npm/@actions/artifact@6.2.1", "pkg:npm/@actions/cache@6.2.0"},
			why:    "yarn fetched @esbuild/linux-x64 at a version it did not install",
		},
		{
			sample: "js-actions-checkout",
			want:   []string{"pkg:npm/@aashutoshrathi/word-wrap@1.2.6", "pkg:npm/@actions/core@3.0.1", "pkg:npm/@actions/exec@3.0.0"},
			why:    "npm installs flat, so its downloads are the only evidence there can be",
		},
		{
			sample: "java-apktool",
			want:   []string{"pkg:maven/antlr/antlr@2.7.7", "pkg:maven/com.android.tools/r8@9.1.31", "pkg:maven/com.beust/jcommander@1.48"},
			why:    "antlr-master is a parent pom Gradle fetched; nothing on disk is a package",
		},
	} {
		if got := selectedFromSample(t, tc.sample); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: %s\n  want: %v\n  got:  %v", tc.sample, tc.why, tc.want, got)
		}
	}
}

// A download that is metadata, not the artifact, is never enough on its own —
// not even from npm: a package manager reads metadata for versions it rejects.
func TestApplyRulesNeverListsAMetadataOnlyPackage(t *testing.T) {
	result := &resolve.Result{Packages: []resolve.Package{{
		PURL: "pkg:npm/semver@7.0.0", Ecosystem: "npm",
		Evidence: []resolve.Evidence{{Source: resolve.SourceNetwork, PkgMgr: "npm", Location: "https://registry.npmjs.org/semver/7.0.0"}},
	}}}

	if got := applyRules(result).Packages; len(got) != 0 {
		t.Fatalf("expected no packages, got %v", got)
	}
}

// An excluded package's paths stay in the result, as unclaimed.
func TestApplyRulesKeepsAnExcludedPackagesFilesAsUnclaimed(t *testing.T) {
	result := &resolve.Result{
		Packages: []resolve.Package{{
			PURL: "pkg:npm/semver@7.0.0", Ecosystem: "npm",
			Evidence: []resolve.Evidence{{Source: resolve.SourceNetwork, PkgMgr: "npm", Location: "https://registry.npmjs.org/semver/7.0.0"}},
			Files:    []resolve.File{{Path: "/b"}},
		}},
		Files: []resolve.File{{Path: "/a"}, {Path: "/c"}},
	}

	out := applyRules(result)
	var got []string
	for _, f := range out.Files {
		got = append(got, f.Path)
	}
	if len(out.Packages) != 0 || strings.Join(got, ",") != "/a,/b,/c" {
		t.Fatalf("expected no packages and files /a,/b,/c, got %v and %v", out.Packages, got)
	}
	if len(result.Files) != 2 {
		t.Fatal("applyRules must not modify its input")
	}
}

// An algorithm with two values is omitted from the node.
func TestSingleValuedHashesOmitsAConflictedAlgorithm(t *testing.T) {
	got := singleValuedHashes([]resolve.Digest{
		{Algorithm: "sha1", Value: "a"},
		{Algorithm: "sha256", Value: "b"},
		{Algorithm: "sha256", Value: "c"},
		{Algorithm: "sha256", Value: "d"},
	})

	if len(got) != 1 || got[int32(sbom.HashAlgorithm_SHA1)] != "a" {
		t.Fatalf("expected only sha1, got %v", got)
	}
}

// By default install paths are included; an artifact download is included
// only where the rules table says so.
func TestShouldInclude(t *testing.T) {
	path := resolve.Evidence{Source: resolve.SourcePath}
	artifact := resolve.Evidence{Source: resolve.SourceNetwork, Artifact: true}
	metadata := resolve.Evidence{Source: resolve.SourceNetwork}

	for _, tc := range []struct {
		ecosystem, pkgMgr string
		e                 resolve.Evidence
		want              bool
	}{
		{"pypi", "pip", path, true},
		{"pypi", "pip", artifact, false},
		{"npm", "pnpm", artifact, false},
		{"npm", "npm", path, true},
		{"npm", "npm", artifact, true},
		{"npm", "npm", metadata, false},
		{"golang", "", artifact, false},
	} {
		tc.e.PkgMgr = tc.pkgMgr
		pkg := resolve.Package{Ecosystem: tc.ecosystem, Evidence: []resolve.Evidence{tc.e}}
		if got := shouldInclude(pkg); got != tc.want {
			t.Errorf("(%s, %s) %s artifact=%v: got %v, want %v",
				tc.ecosystem, tc.pkgMgr, tc.e.Source, tc.e.Artifact, got, tc.want)
		}
	}
}

// A new package manager is handled by adding its pair to rules.
func TestRulesAreKeyedByEcosystemAndPackageManager(t *testing.T) {
	key := ruleKey{ecosystem: "pypi", pkgMgr: "uv"}
	rules[key] = rule{includePaths: true, includeDownloads: true}
	t.Cleanup(func() { delete(rules, key) })

	pkg := resolve.Package{Ecosystem: "pypi", Evidence: []resolve.Evidence{
		{Source: resolve.SourceNetwork, PkgMgr: "uv", Artifact: true},
	}}
	if !shouldInclude(pkg) {
		t.Error("a uv download should be included once (pypi, uv) has a rule for it")
	}
	pkg.Evidence[0].PkgMgr = "pip"
	if shouldInclude(pkg) {
		t.Error("a pip download is still covered by the default rule")
	}
}
