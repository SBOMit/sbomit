package resolver

import (
	"sort"
	"testing"
)

func filtered(paths ...string) []string {
	files := make([]FileInfo, 0, len(paths))
	for _, p := range paths {
		files = append(files, FileInfo{Path: p})
	}
	var out []string
	for _, f := range NewFileFilter().Filter(files) {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A base whose environment was used is dropped; the environment is kept.
func TestFileFilterExcludesACondaBaseWhoseEnvironmentWasUsed(t *testing.T) {
	const base = "/home/jake/miniforge3"
	env := base + "/envs/rioxarray"

	got := filtered(
		base+"/conda-meta/httpx-0.28.1-pyhd8ed1ab_0.json",
		base+"/lib/python3.14/site-packages/httpx-0.28.1.dist-info/METADATA",
		base+"/bin/conda",
		base+"/.condarc",
		env+"/conda-meta/affine-3.0.1-pyhecae5ae_0.json",
		env+"/lib/python3.12/site-packages/affine-3.0.1.dist-info/METADATA",
	)

	want := []string{
		env + "/conda-meta/affine-3.0.1-pyhecae5ae_0.json",
		env + "/lib/python3.12/site-packages/affine-3.0.1.dist-info/METADATA",
	}
	if !sameStrings(got, want) {
		t.Fatalf("expected only the project environment\n  want: %v\n  got:  %v", want, got)
	}
}

// The default package cache (pkgs/) is kept.
func TestFileFilterKeepsTheDefaultCondaPackageCache(t *testing.T) {
	const base = "/home/jake/miniforge3"

	got := filtered(
		base+"/conda-meta/conda-26.7.2-py314h9e666f3_1.json",
		base+"/envs/rioxarray/conda-meta/affine-3.0.1-pyhecae5ae_0.json",
		base+"/pkgs/affine-3.0.1-pyhecae5ae_0.conda",
		base+"/pkgs/affine-3.0.1-pyhecae5ae_0/info/index.json",
	)

	for _, keep := range []string{
		base + "/pkgs/affine-3.0.1-pyhecae5ae_0.conda",
		base + "/pkgs/affine-3.0.1-pyhecae5ae_0/info/index.json",
	} {
		if !contains(got, keep) {
			t.Errorf("the package cache must be kept: %s missing from %v", keep, got)
		}
	}
	if contains(got, base+"/conda-meta/conda-26.7.2-py314h9e666f3_1.json") {
		t.Error("the base's own install record should be excluded")
	}
}

// A base with no environments is the project's environment and is kept.
func TestFileFilterKeepsABaseThatIsTheOnlyEnvironment(t *testing.T) {
	paths := []string{
		"/opt/conda/conda-meta/numpy-2.1.0-py312h1234567_0.json",
		"/opt/conda/lib/python3.12/site-packages/numpy-2.1.0.dist-info/METADATA",
	}
	if got := filtered(paths...); !sameStrings(got, paths) {
		t.Fatalf("a base with no environment must be kept whole, got %v", got)
	}
}

// Both install records and an environment are needed to identify a base.
func TestFileFilterNeedsBothRecordsAndAnEnvironment(t *testing.T) {
	paths := []string{
		"/app/node_modules/dotenv-cli/envs/production/config.json",
		"/app/node_modules/dotenv-cli/package.json",
		"/srv/tool/envs/dev/settings.toml",
	}
	if got := filtered(paths...); !sameStrings(got, paths) {
		t.Fatalf("nothing here is a conda installation, got %v", got)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
