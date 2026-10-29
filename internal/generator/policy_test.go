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
	for _, p := range selectPackages(result).Packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

// Download-only packages are listed only when npm fetched them.
func TestSelectPackagesKeepsDownloadsOnlyWhereNoPathCouldShowThem(t *testing.T) {
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
func TestSelectPackagesNeverListsAMetadataOnlyPackage(t *testing.T) {
	result := &resolve.Result{Packages: []resolve.Package{{
		ID: "x", PURL: "pkg:npm/semver@7.0.0", Ecosystem: "npm",
		Evidence: []resolve.Evidence{{Source: resolve.SourceNetwork, PkgMgr: "npm", Location: "https://registry.npmjs.org/semver/7.0.0"}},
	}}}

	if got := selectPackages(result).Packages; len(got) != 0 {
		t.Fatalf("expected no packages, got %v", got)
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
