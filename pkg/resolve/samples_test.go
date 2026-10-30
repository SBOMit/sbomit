package resolve

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// End-to-end tests, one per ecosystem and package manager, on attestations
// distilled from real witness runs (test/<ecosystem>-<project>.json).
type sampleCase struct {
	name string

	// packages the sample must yield, exactly.
	packages []string

	// downloadOnly are packages seen only in the network trace.
	downloadOnly []string

	// pkgmgr is the package manager every piece of evidence must name;
	// pkgmgrs overrides it per package.
	pkgmgr  string
	pkgmgrs map[string]string

	// digested maps packages to the registry-verified digest they must claim.
	digested map[string]string

	// evidenceSuffix is what each package's cited path must end with, unless
	// evidence overrides it for a package.
	evidenceSuffix string
	evidence       map[string]string

	why string
}

func TestResolveSamples(t *testing.T) {
	cases := []sampleCase{
		{
			name: "js-pnpm-action-setup",
			packages: []string{
				"pkg:npm/@actions/cache@4.1.0",
				"pkg:npm/@actions/core@1.11.1",
				"pkg:npm/@actions/exec@1.1.1",
				"pkg:npm/@azure/core-paging@1.6.2",
			},
			downloadOnly:   []string{"pkg:npm/@azure/core-paging@1.6.2"},
			pkgmgr:         "pnpm",
			evidenceSuffix: "/package.json",
			why:            "pnpm's virtual store names the package and version in the store directory",
		},
		{
			name: "js-docker-login-action",
			packages: []string{
				"pkg:npm/@aashutoshrathi/word-wrap@1.2.6",
				"pkg:npm/@actions/artifact@6.2.1",
				"pkg:npm/@actions/cache@6.2.0",
				"pkg:npm/@esbuild/linux-x64@0.28.0",
			},
			downloadOnly:   []string{"pkg:npm/@esbuild/linux-x64@0.28.0"},
			pkgmgr:         "yarn",
			evidenceSuffix: ".zip",
			why:            "yarn berry's cache filename carries name and version; the zip is yarn's repack, not npm's tarball",
		},
		{
			name: "js-actions-checkout",
			packages: []string{
				"pkg:npm/@aashutoshrathi/word-wrap@1.2.6",
				"pkg:npm/@actions/core@3.0.1",
				"pkg:npm/@actions/exec@3.0.0",
			},
			downloadOnly: []string{
				"pkg:npm/@aashutoshrathi/word-wrap@1.2.6",
				"pkg:npm/@actions/core@3.0.1",
				"pkg:npm/@actions/exec@3.0.0",
			},
			pkgmgr: "npm",
			why:    "npm installs flat, so no path carries a version: the download is the only evidence",
		},
		{
			name: "python-in-toto",
			packages: []string{
				"pkg:pypi/attrs@26.1.0",
				"pkg:pypi/build@1.6.1",
				"pkg:pypi/cffi@2.0.0",
			},
			pkgmgr: "pip",
			digested: map[string]string{
				"pkg:pypi/attrs@26.1.0": "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309",
				"pkg:pypi/cffi@2.0.0":   "3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba",
			},
			evidenceSuffix: "/METADATA",
			why: "a pip install is cited to its METADATA; its digest is the wheel's, recorded empty on disk while " +
				"pip wrote it and correctly in the download — build's wheel was never fetched",
		},
		{
			name: "python-rioxarray",
			packages: []string{
				"pkg:conda/_openmp_mutex@4.5?build=20_gnu",
				"pkg:conda/_python_abi3_support@1.0?build=hd8ed1ab_3",
				"pkg:conda/affine@3.0.1?build=pyhecae5ae_0",
				"pkg:conda/msgpack-python@1.2.3?build=py312h9be0db6_0",
				"pkg:conda/setuptools@84.0.0?build=pyh332efcf_0",
				"pkg:pypi/pyproj@3.8.0",
			},
			pkgmgr:  "conda",
			pkgmgrs: map[string]string{"pkg:pypi/pyproj@3.8.0": "pip"},
			digested: map[string]string{
				"pkg:conda/_openmp_mutex@4.5?build=20_gnu":             "1dd3fffd892081df9726d7eb7e0dea6198962ba775bd88842135a4ddb4deb3c9",
				"pkg:conda/_python_abi3_support@1.0?build=hd8ed1ab_3":  "2a7204314663eeda5dec482a956f0e2eaf289bd5b9953eaaaad0e81aa64638f2",
				"pkg:conda/affine@3.0.1?build=pyhecae5ae_0":            "8801cd5b4e0f0203b7a18e8def15929f3413e93e2da88d5b918b735454106f85",
				"pkg:conda/msgpack-python@1.2.3?build=py312h9be0db6_0": "46b34715512392aec0478da2b973f88d9340493f82cf7a610918b049b15e31b8",
				"pkg:conda/setuptools@84.0.0?build=pyh332efcf_0":       "9e200ee5f9ff19a4d94e4b51c4856d53dec849f91032f345cf0c6bc3d51a7183",
				"pkg:pypi/pyproj@3.8.0":                                "6b34cec6bdd66b721980c003cc2a0fce0cab7949444ad037fc2a7ecb6f3b996c",
			},
			evidenceSuffix: ".conda",
			evidence: map[string]string{
				"pkg:pypi/pyproj@3.8.0": "/METADATA",
			},
			why: "a conda package is conda's, not PyPI's — including its dist-info in an environment under a " +
				"renamed distribution — while a pip install into the environment stays PyPI's, and conda's " +
				"own base installation (httpx, a second python) is no package of the project's",
		},
		{
			name: "go-duf",
			packages: []string{
				"pkg:golang/github.com/IGLOU-EU/go-wildcard@v1.0.3",
				"pkg:golang/github.com/aymanbagabas/go-osc52/v2@v2.0.1",
				"pkg:golang/github.com/clipperhouse/uax29/v2@v2.2.0",
			},
			pkgmgr:         "go",
			evidenceSuffix: ".zip",
			why:            "the module zip in the download cache is what the proxy serves; go.sum hashes something else",
		},
		{
			name: "go-redka",
			packages: []string{
				"pkg:golang/github.com/lib/pq@v1.11.1",
				"pkg:golang/github.com/mattn/go-sqlite3@v1.14.33",
				"pkg:golang/github.com/tidwall/btree@v1.7.0",
			},
			pkgmgr:         "go",
			evidenceSuffix: ".zip",
			why:            "cgo changes nothing about how modules are laid out",
		},
		{
			name: "go-lazydocker",
			why:  "vendored source has no version anywhere and the build made no network requests, so there is no evidence of any kind",
		},
		{
			name: "rust-hexyl",
			packages: []string{
				"pkg:cargo/anstream@0.6.17",
				"pkg:cargo/anstyle-parse@0.2.6",
				"pkg:cargo/anstyle-query@1.1.2",
				"pkg:cargo/clap_complete@4.5.55",
				"pkg:cargo/linux-raw-sys@0.4.14",
			},
			pkgmgr: "cargo",
			digested: map[string]string{
				"pkg:cargo/anstream@0.6.17":      "23a1e53f0f5d86382dafe1cf314783b2044280f406e7e1506368220ad11b1338",
				"pkg:cargo/anstyle-parse@0.2.6":  "3b2d16507662817a6a20a9ea92df6652ee4f94f914589377d69f3b21bc5798a9",
				"pkg:cargo/anstyle-query@1.1.2":  "79947af37f4177cfead1110013d678905c37501914fba0efea834c3fe9a8d60c",
				"pkg:cargo/clap_complete@4.5.55": "a5abde44486daf70c5be8b8f8f1b66c49f86236edf6fa2abadb4d961c4c6229a",
				"pkg:cargo/linux-raw-sys@0.4.14": "78b3ae25bc7c8c38cec158d1f2757ee79e9b3740fbc7ccf0e59e4b08d793fa89",
			},
			evidenceSuffix: ".crate",
			why: "the .crate is what crates.io publishes; clap_complete's and linux-raw-sys's were recorded empty " +
				"on disk, and their digests come from the download",
		},
		{
			name: "java-google-java-format",
			packages: []string{
				"pkg:maven/biz.aQute.bnd/biz.aQute.bnd.embedded-repo@7.2.3",
				"pkg:maven/biz.aQute.bnd/biz.aQute.bnd.util@7.2.3",
				"pkg:maven/biz.aQute.bnd/biz.aQute.bndlib@7.2.3",
			},
			pkgmgr:         "maven",
			evidenceSuffix: ".jar",
			why: "this repository is at -Dmaven.repo.local, not ~/.m2, which the layout match has to tolerate; " +
				"its p2 bundles name no Maven coordinates",
		},
		{
			name: "java-apktool",
			packages: []string{
				"pkg:maven/antlr/antlr@2.7.7",
				"pkg:maven/com.android.tools/r8@9.1.31",
				"pkg:maven/com.beust/jcommander@1.48",
				"pkg:maven/org.antlr/antlr-master@3.5.2",
			},
			downloadOnly:   []string{"pkg:maven/org.antlr/antlr-master@3.5.2"},
			pkgmgr:         "gradle",
			evidenceSuffix: ".jar",
			why:            "Gradle's cache resolves Maven coordinates, with the artifact's sha1 as a directory name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := resolveSample(t, tc.name)

			got := purlsOf(result)
			if strings.Join(got, "\n") != strings.Join(tc.packages, "\n") {
				t.Fatalf("%s\n  want: %v\n  got:  %v", tc.why, tc.packages, got)
			}

			if len(tc.packages) == 0 {
				// Needs real vendor paths, or this passes on an empty sample.
				if len(result.Files) < 5 {
					t.Fatalf("only %d paths reached the resolvers; this case needs a real "+
						"sample of the layout to assert anything", len(result.Files))
				}
				var inLayout int
				for _, f := range result.Files {
					if strings.Contains(f.Path, "/vendor/") {
						inLayout++
					}
				}
				if inLayout == 0 {
					t.Fatal("no vendored paths in the sample, so the assertion is vacuous")
				}
				return
			}

			owners := make(map[string]int, len(result.Relationships))
			for _, rel := range result.Relationships {
				pkg, ok := result.PackageByID(rel.FromPackageID)
				if !ok {
					t.Fatalf("relationship names unknown package %q", rel.FromPackageID)
				}
				owners[pkg.PURL]++
			}

			for _, p := range result.Packages {
				if want := strings.SplitN(strings.TrimPrefix(p.PURL, "pkg:"), "/", 2)[0]; p.Ecosystem != want {
					t.Errorf("%s reported as %q, want its PURL type %q", p.PURL, p.Ecosystem, want)
				}

				pkgmgr := tc.pkgmgr
				if m, ok := tc.pkgmgrs[p.PURL]; ok {
					pkgmgr = m
				}
				for _, e := range p.Evidence {
					if e.PkgMgr != pkgmgr {
						t.Errorf("%s: evidence %s names pkgmgr %q, want %q", p.PURL, e.Location, e.PkgMgr, pkgmgr)
					}
				}

				var digest string
				if len(p.Digests) == 1 && p.Digests[0].Algorithm == "sha256" {
					digest = p.Digests[0].Value
				} else if len(p.Digests) > 1 {
					t.Errorf("%s claims %d digests, want at most one sha256", p.PURL, len(p.Digests))
				}
				if want := tc.digested[p.PURL]; digest != want {
					t.Errorf("%s claims digest %q, want %q", p.PURL, digest, want)
				}

				cited := citations(result, p)
				if slices.Contains(tc.downloadOnly, p.PURL) {
					for _, e := range p.Evidence {
						if e.Source != SourceNetwork {
							t.Errorf("%s should rest on downloads alone, got %+v", p.PURL, e)
						}
					}
					if len(cited) != 0 || owners[p.PURL] != 0 {
						t.Errorf("%s was never observed on disk, but cites %v and owns %d files",
							p.PURL, cited, owners[p.PURL])
					}
					continue
				}

				suffix := tc.evidenceSuffix
				if s, ok := tc.evidence[p.PURL]; ok {
					suffix = s
				}
				if len(cited) != 1 {
					t.Errorf("%s cites %d paths, want exactly one", p.PURL, len(cited))
				} else if !strings.HasSuffix(cited[0], suffix) {
					t.Errorf("%s cites %q, want a path ending in %q", p.PURL, cited[0], suffix)
				}
				if owners[p.PURL] == 0 {
					t.Errorf("%s owns no files, but its contents were observed", p.PURL)
				}
			}
		})
	}
}

// No empty-content digest may reach the result. The value is spelled out
// here so the test does not share a defect with the code.
func TestResolveSamplesCarryNoEmptyContentDigest(t *testing.T) {
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	var inFixtures int
	for _, name := range sampleNames(t) {
		raw, err := os.ReadFile(filepath.Join("..", "..", "test", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		inFixtures += strings.Count(string(raw), `"sha256": "`+emptySHA256+`"`)

		result := resolveSample(t, name)
		check := func(where string, digests []Digest) {
			for _, d := range digests {
				if d.Value == emptySHA256 {
					t.Errorf("%s: %s carries the empty-content digest", name, where)
				}
			}
		}
		for _, p := range result.Packages {
			check(p.PURL, p.Digests)
			for _, e := range p.Evidence {
				check(e.Location, e.Digests)
			}
		}
		for _, f := range result.Files {
			check(f.Path, f.Digests)
		}
	}
	if inFixtures == 0 {
		t.Fatal("no sample records an empty-content digest, so this test asserts nothing")
	}
}

// Tycho's p2 cache sits inside the Maven repository with Maven-shaped paths. Its
// paths must reach the result unclaimed, rather than as invented coordinates.
func TestResolveSamplesLeaveP2BundlesUnclaimed(t *testing.T) {
	result := resolveSample(t, "java-google-java-format")

	var p2 int
	for _, f := range result.UnownedFiles() {
		if strings.Contains(f.Path, "/repository/p2/") {
			p2++
		}
	}
	if p2 == 0 {
		t.Fatal("the sample carries no p2 path, so the package list proves nothing about p2")
	}
}

// conda's base installation is dropped; the project environment is kept.
func TestResolveSamplesExcludeTheCondaBaseInstallation(t *testing.T) {
	const base = "/home/jake/miniforge3/"

	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "python-rioxarray.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), base+"conda-meta/httpx-0.28.1") {
		t.Fatal("the sample carries no base-installation path, so this test asserts nothing")
	}

	result := resolveSample(t, "python-rioxarray")
	for _, f := range result.Files {
		if strings.HasPrefix(f.Path, base) && !strings.HasPrefix(f.Path, base+"envs/") {
			t.Errorf("a base-installation path reached the result: %s", f.Path)
		}
	}
	var env int
	for _, f := range result.Files {
		if strings.HasPrefix(f.Path, base+"envs/rioxarray/") {
			env++
		}
	}
	if env == 0 {
		t.Fatal("the project environment's paths must be kept")
	}
}

func resolveSample(t *testing.T, name string) *Result {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", name+".json"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	result, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("%s: resolve: %v", name, err)
	}
	return result
}

func sampleNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("..", "..", "test"))
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			out = append(out, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return out
}

// Invariants every sample must hold, including identical output across runs.
func TestResolveSamplesAreSelfConsistent(t *testing.T) {
	names := sampleNames(t)
	if len(names) != 12 {
		t.Errorf("expected 11 samples plus orjson_witness, found %d; was one added without a case above?", len(names))
	}

	for _, name := range names {
		result := resolveSample(t, name)

		for _, p := range result.Packages {
			if p.ID == "" || p.Name == "" || p.Ecosystem == "" || p.PURL == "" || len(p.Evidence) == 0 {
				t.Errorf("%s: %s is missing a required field: %+v", name, p.PURL, p)
			}
		}

		var evident int
		for _, rel := range result.Relationships {
			if _, ok := result.PackageByID(rel.FromPackageID); !ok {
				t.Errorf("%s: relationship names unknown package %q", name, rel.FromPackageID)
			}
			switch rel.Type {
			case EvidentBy:
				evident++
			case Contains:
			default:
				t.Errorf("%s: unexpected relationship type %q", name, rel.Type)
			}
		}

		var withPath int
		for _, p := range result.Packages {
			if slices.ContainsFunc(p.Evidence, func(e Evidence) bool { return e.Source == SourcePath }) {
				withPath++
			}
		}
		if evident != withPath {
			t.Errorf("%s: %d evident-by edges for %d packages with path evidence", name, evident, withPath)
		}

		if first, again := fingerprint(result), fingerprint(resolveSample(t, name)); first != again {
			t.Errorf("%s: two runs on the same input differ", name)
		}
	}
}

// fingerprint is the full output in order, so any order-dependence shows.
func fingerprint(r *Result) string {
	var sb strings.Builder
	for _, p := range r.Packages {
		sb.WriteString(p.ID + " " + p.PURL + "\n")
		for _, e := range p.Evidence {
			sb.WriteString("  " + string(e.Source) + " " + e.Location + "\n")
		}
	}
	for _, rel := range r.Relationships {
		sb.WriteString(string(rel.Type) + " " + rel.FromPackageID + " " + rel.ToPath + "\n")
	}
	for _, f := range r.Files {
		sb.WriteString(f.Path + "\n")
	}
	return sb.String()
}
