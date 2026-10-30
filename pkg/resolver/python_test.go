package resolver

import (
	"sort"
	"strings"
	"testing"
)

// Paths follow the shapes observed in results/python: a venv at a custom root,
// and conda packages that contain a site-packages directory of their own.
const (
	venvSitePackages  = "/home/jake/venvs/python/in-toto/lib/python3.12/site-packages"
	condaSitePackages = "/home/jake/conda-pkgs/rioxarray/setuptools-84.0.0-pyh332efcf_0/site-packages"
)

func pypiPURLs(packages []PackageInfo) []string {
	out := make([]string, 0, len(packages))
	for _, p := range packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

func TestPythonResolverResolvesDistInfo(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: venvSitePackages + "/attrs-26.1.0.dist-info/METADATA"},
		{Path: venvSitePackages + "/attrs-26.1.0.dist-info/RECORD"},
		{Path: venvSitePackages + "/attr/__init__.py"},
	})

	got := pypiPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:pypi/attrs@26.1.0" {
		t.Fatalf("expected pkg:pypi/attrs@26.1.0, got %v", got)
	}

	// METADATA declares the distribution; RECORD is installer bookkeeping.
	want := venvSitePackages + "/attrs-26.1.0.dist-info/METADATA"
	if len(packages[0].Locations) != 1 || packages[0].Locations[0] != want {
		t.Fatalf("expected METADATA to be cited, got %v", packages[0].Locations)
	}
}

// The -pyX.Y tag in an egg-info name is not part of the version.
func TestPythonResolverStripsEggInfoPythonTag(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: condaSitePackages + "/setuptools-84.0.0-py3.10.egg-info/PKG-INFO"},
	})

	got := pypiPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:pypi/setuptools@84.0.0" {
		t.Fatalf("expected pkg:pypi/setuptools@84.0.0, got %v", got)
	}
}

func TestPythonResolverNormalizesNamePerPEP503(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: venvSitePackages + "/pyproject_hooks-1.3.3.dist-info/METADATA"},
		{Path: venvSitePackages + "/python_dateutil-2.9.0.post0.dist-info/METADATA"},
	})

	got := pypiPURLs(packages)
	want := []string{"pkg:pypi/pyproject-hooks@1.3.3", "pkg:pypi/python-dateutil@2.9.0.post0"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestPythonResolverAttributesPackageFiles(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: venvSitePackages + "/attrs-26.1.0.dist-info/METADATA"},
	})

	filters := r.OwnershipFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected one ownership filter, got %d", len(filters))
	}

	// attrs installs its module as "attr", which getPythonPackageDirVariants
	// does not cover — the dist-info directory itself must still be owned.
	owned := venvSitePackages + "/attrs-26.1.0.dist-info/RECORD"
	if !filters[0].Matcher.Matches(NewPath(owned)) {
		t.Fatalf("expected attrs to own %s", owned)
	}

	foreign := venvSitePackages + "/certifi-2026.1.1.dist-info/METADATA"
	if filters[0].Matcher.Matches(NewPath(foreign)) {
		t.Fatalf("did not expect attrs to own %s", foreign)
	}
}

func TestPythonResolverPassesNonPythonPathsThrough(t *testing.T) {
	r := NewPythonResolver()

	_, remaining := r.Resolve([]FileInfo{
		{Path: "/etc/ld.so.cache"},
		{Path: "/home/jake/projects/python/in-toto/pyproject.toml"},
	})

	if len(remaining) != 2 {
		t.Fatalf("expected both non-Python paths to flow on, got %d", len(remaining))
	}
}

const pipUnpack = "/tmp/pip-unpack-3cnj8pgz"

// The staged wheel is the artifact; METADATA stays the citation.
func TestPythonResolverTakesArtifactFromStagedWheel(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{
			Path:    venvSitePackages + "/anyio-4.12.0.dist-info/METADATA",
			Digests: []Digest{{Algorithm: "sha256", Value: "metadata-digest"}},
		},
		{
			Path:    pipUnpack + "/anyio-4.12.0-py3-none-any.whl",
			Digests: []Digest{{Algorithm: "sha256", Value: "wheel-digest"}},
		},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d: %v", len(packages), pypiPURLs(packages))
	}
	if a := packages[0].Artifact; a == nil || digestValue(a.Digests, "sha256") != "wheel-digest" {
		t.Fatalf("expected the staged wheel as the artifact, got %+v", a)
	}
	if !strings.HasSuffix(packages[0].Locations[0], "/METADATA") {
		t.Fatalf("expected METADATA to remain the citation, got %v", packages[0].Locations)
	}
}

// Locally built wheels are not packages.
func TestPythonResolverIgnoresLocallyBuiltWheels(t *testing.T) {
	r := NewPythonResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/root/orjson/target/wheels/orjson-3.11.4-cp312-cp312-manylinux_2_34_aarch64.whl"},
		{Path: "/home/jake/projects/python/in-toto/dist/in_toto-3.0.0-py3-none-any.whl"},
		{Path: "/tmp/pip-ephem-wheel-cache-x/wheels/1f/rioxarray-0.23.1.dev0-py3-none-any.whl"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages from locally built wheels, got %v", pypiPURLs(packages))
	}
	if len(remaining) != 3 {
		t.Fatalf("expected all three to flow on, got %d", len(remaining))
	}
}

// A wheel and its dist-info resolve to one package.
func TestPythonResolverMatchesWheelNameToDistInfo(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: venvSitePackages + "/python_dateutil-2.9.0.post0.dist-info/METADATA"},
		{
			Path:    pipUnpack + "/python_dateutil-2.9.0.post0-py2.py3-none-any.whl",
			Digests: []Digest{{Algorithm: "sha256", Value: "wheel-digest"}},
		},
	})

	got := pypiPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:pypi/python-dateutil@2.9.0.post0" {
		t.Fatalf("expected one package, got %v", got)
	}
	if a := packages[0].Artifact; a == nil || digestValue(a.Digests, "sha256") != "wheel-digest" {
		t.Fatalf("expected the wheel as the artifact, got %+v", a)
	}

	// And the wheel must be attributed to it, not left unowned.
	filters := r.OwnershipFilters(packages)
	wheel := pipUnpack + "/python_dateutil-2.9.0.post0-py2.py3-none-any.whl"
	if !filters[0].Matcher.Matches(NewPath(wheel)) {
		t.Fatalf("expected the package to own %s", wheel)
	}
}

// METADATA outranks the wheel, which outranks other files.
func TestPythonResolverRanksWheelBetweenMetadataAndOtherFiles(t *testing.T) {
	r := NewPythonResolver()

	// No METADATA: the wheel is the best available citation.
	wheelCited, _ := r.Resolve([]FileInfo{
		{Path: venvSitePackages + "/packaging-26.3.dist-info/entry_points.txt"},
		{Path: pipUnpack + "/packaging-26.3-py3-none-any.whl"},
	})
	if len(wheelCited) != 1 || !strings.HasSuffix(wheelCited[0].Locations[0], ".whl") {
		t.Fatalf("expected the wheel to be cited, got %v", wheelCited[0].Locations)
	}

	// With METADATA present, it wins.
	metadataCited, _ := r.Resolve([]FileInfo{
		{Path: venvSitePackages + "/packaging-26.3.dist-info/entry_points.txt"},
		{Path: venvSitePackages + "/packaging-26.3.dist-info/METADATA"},
		{Path: pipUnpack + "/packaging-26.3-py3-none-any.whl"},
	})
	if len(metadataCited) != 1 || !strings.HasSuffix(metadataCited[0].Locations[0], "/METADATA") {
		t.Fatalf("expected METADATA to be cited, got %v", metadataCited[0].Locations)
	}
}

// Paths follow the shapes observed in results/python/rioxarray, whose
// CONDA_PKGS_DIRS is "conda-pkgs/" rather than the default "pkgs/".
const condaCache = "/home/jake/generate_att/conda-pkgs/rioxarray"

func condaPURLs(packages []PackageInfo) []string {
	out := make([]string, 0, len(packages))
	for _, p := range packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

// A conda cache root is found by its packages' info/ directories.
func TestPythonResolverCondaResolvesPackageCache(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: condaCache + "/affine-3.0.1-pyhecae5ae_0/info/index.json"},
		{Path: condaCache + "/affine-3.0.1-pyhecae5ae_0/site-packages/affine/__init__.py"},
		{
			Path:    condaCache + "/affine-3.0.1-pyhecae5ae_0.conda",
			Digests: []Digest{{Algorithm: "sha256", Value: "archive-digest"}},
		},
	})

	got := condaPURLs(packages)
	want := "pkg:conda/affine@3.0.1?build=pyhecae5ae_0"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected %s, got %v", want, got)
	}
	if packages[0].PkgMgr != "conda" {
		t.Fatalf("expected manager conda, got %q", packages[0].PkgMgr)
	}

	// The .conda is what the channel published.
	if a := packages[0].Artifact; a == nil || digestValue(a.Digests, "sha256") != "archive-digest" {
		t.Fatalf("expected the .conda file as the artifact, got %+v", a)
	}
}

// Without info/ there is no cache root, so nothing is claimed as conda.
func TestPythonResolverCondaNeedsACacheRoot(t *testing.T) {
	r := NewPythonResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/home/jake/venvs/in-toto/lib/python3.12/site-packages/attrs-26.1.0.dist-info/METADATA"},
		{Path: "/some/dir/foo-1.2.3-abc_0/bar.txt"},
	})

	for _, p := range packages {
		if p.Ecosystem == "conda" {
			t.Fatalf("expected no conda packages without a cache root, got %v", condaPURLs(packages))
		}
	}
	var found bool
	for _, f := range remaining {
		found = found || f.Path == "/some/dir/foo-1.2.3-abc_0/bar.txt"
	}
	if !found {
		t.Fatalf("the unrelated path must flow on, got %v", remaining)
	}
}

// The build string is kept as a PURL qualifier.
func TestPythonResolverCondaKeepsTheBuildString(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: condaCache + "/numpy-2.1.0-py312h1234567_0/info/index.json"},
		{Path: condaCache + "/numpy-2.1.0-py313h7654321_0/info/index.json"},
	})

	got := condaPURLs(packages)
	want := []string{
		"pkg:conda/numpy@2.1.0?build=py312h1234567_0",
		"pkg:conda/numpy@2.1.0?build=py313h7654321_0",
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected both builds, got %v", got)
	}
}

// An environment's dist-info for a conda package is conda's.
func TestPythonResolverCondaClaimsEnvironmentCopies(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: condaCache + "/affine-3.0.1-pyhecae5ae_0/info/index.json"},
		{Path: "/home/jake/miniforge3/envs/rioxarray/lib/python3.12/site-packages/affine-3.0.1.dist-info/METADATA"},
	})

	got := condaPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:conda/affine@3.0.1?build=pyhecae5ae_0" {
		t.Fatalf("the environment copy must not become a PyPI package, got %v", got)
	}
}

// A package pip installed into a conda environment is genuinely PyPI's, and
// must flow on — rioxarray itself is installed that way in the fixture.
func TestPythonResolverCondaLetsPipInstallsThrough(t *testing.T) {
	r := NewPythonResolver()

	pipInstalled := "/home/jake/miniforge3/envs/rioxarray/lib/python3.12/site-packages/rioxarray-0.23.1.dist-info/METADATA"
	packages, _ := r.Resolve([]FileInfo{
		{Path: condaCache + "/affine-3.0.1-pyhecae5ae_0/info/index.json"},
		{Path: pipInstalled},
	})

	got := condaPURLs(packages)
	want := []string{"pkg:conda/affine@3.0.1?build=pyhecae5ae_0", "pkg:pypi/rioxarray@0.23.1"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("a pip install into a conda environment must be reported as PyPI: got %v", got)
	}
}

func TestPythonResolverCondaAttributesPackageFiles(t *testing.T) {
	r := NewPythonResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: condaCache + "/affine-3.0.1-pyhecae5ae_0/info/index.json"},
	})

	filters := r.OwnershipFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected one ownership filter, got %d", len(filters))
	}

	for _, owned := range []string{
		condaCache + "/affine-3.0.1-pyhecae5ae_0/site-packages/affine/__init__.py",
		condaCache + "/affine-3.0.1-pyhecae5ae_0.conda",
	} {
		if !filters[0].Matcher.Matches(NewPath(owned)) {
			t.Errorf("expected affine to own %s", owned)
		}
	}

	foreign := condaCache + "/affine-3.0.2-pyhecae5ae_0/info/index.json"
	if filters[0].Matcher.Matches(NewPath(foreign)) {
		t.Fatalf("did not expect 3.0.1 to own %s", foreign)
	}
}

// A conda package containing Python code is reported as conda.
func TestResolverChainPrefersCondaOverPyPI(t *testing.T) {
	result := NewResolverChain().ResolveAll([]FileInfo{
		{Path: condaCache + "/affine-3.0.1-pyhecae5ae_0/info/index.json"},
		{Path: condaCache + "/affine-3.0.1-pyhecae5ae_0/site-packages/affine-3.0.1.dist-info/METADATA"},
		{Path: condaCache + "/_openmp_mutex-4.5-20_gnu/info/index.json"},
	})

	got := condaPURLs(result.Packages)
	want := []string{
		"pkg:conda/_openmp_mutex@4.5?build=20_gnu",
		"pkg:conda/affine@3.0.1?build=pyhecae5ae_0",
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

// conda-meta records decide which site-packages entries are conda's.
func TestPythonResolverCondaClaimsPrefixPackagesFromInstallRecords(t *testing.T) {
	const base = "/home/jake/miniforge3"
	result := NewResolverChain().ResolveAll([]FileInfo{
		{Path: base + "/conda-meta/httpx-0.28.1-pyhd8ed1ab_0.json"},
		{Path: base + "/lib/python3.12/site-packages/httpx-0.28.1.dist-info/METADATA"},
		// Not in the prefix's records: pip put it there.
		{Path: base + "/lib/python3.12/site-packages/pyproj-3.8.0.dist-info/METADATA"},
	})

	got := condaPURLs(result.Packages)
	want := []string{"pkg:conda/httpx@0.28.1?build=pyhd8ed1ab_0", "pkg:pypi/pyproj@3.8.0"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

// conda-forge renames some PyPI projects. msgpack-python installs the msgpack
// distribution; matching on the conda name alone reported it twice.
func TestPythonResolverCondaMatchesRenamedDistributions(t *testing.T) {
	const env = "/home/jake/miniforge3/envs/rioxarray"
	result := NewResolverChain().ResolveAll([]FileInfo{
		{Path: env + "/conda-meta/msgpack-python-1.2.3-py312h9be0db6_0.json"},
		{Path: env + "/lib/python3.12/site-packages/msgpack-1.2.3.dist-info/METADATA"},
		{Path: env + "/conda-meta/setuptools-84.0.0-pyh332efcf_0.json"},
		{Path: env + "/lib/python3.12/site-packages/setuptools-84.0.0-py3.10.egg-info/PKG-INFO"},
	})

	got := condaPURLs(result.Packages)
	want := []string{
		"pkg:conda/msgpack-python@1.2.3?build=py312h9be0db6_0",
		"pkg:conda/setuptools@84.0.0?build=pyh332efcf_0",
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected only the conda packages, got %v", got)
	}
}

// A dist-info inside a cached conda package belongs to that package.
func TestPythonResolverCondaOwnsDistInfoNestedInACachePackage(t *testing.T) {
	pkgDir := condaCache + "/msgpack-python-1.2.3-py312h9be0db6_0"
	result := NewResolverChain().ResolveAll([]FileInfo{
		{Path: pkgDir + "/info/index.json"},
		{Path: pkgDir + "/lib/python3.12/site-packages/msgpack-1.2.3.dist-info/METADATA"},
	})

	got := condaPURLs(result.Packages)
	if len(got) != 1 || got[0] != "pkg:conda/msgpack-python@1.2.3?build=py312h9be0db6_0" {
		t.Fatalf("expected one conda package, got %v", got)
	}
}

// artifactDigest is the given algorithm's digest of a package's artifact, or
// "" when it has no artifact or none was recorded.
func artifactDigest(pkg PackageInfo, algorithm string) string {
	if pkg.Artifact == nil {
		return ""
	}
	return digestValue(pkg.Artifact.Digests, algorithm)
}

func digestValue(digests []Digest, algorithm string) string {
	for _, d := range digests {
		if d.Algorithm == algorithm {
			return d.Value
		}
	}
	return ""
}
