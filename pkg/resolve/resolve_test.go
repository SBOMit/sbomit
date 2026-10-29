package resolve

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sbomit/sbomit/pkg/attestation"
)

func TestResolveAttestationsDirect(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "python-rioxarray.json"))
	if err != nil {
		t.Fatalf("failed to read test attestation: %v", err)
	}

	attestations, err := attestation.ParseWitnessData(data, nil)
	if err != nil {
		t.Fatalf("failed to parse witness data: %v", err)
	}

	resultFromBytes, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	resultFromParsed, err := ResolveAttestations(attestations, Options{})
	if err != nil {
		t.Fatalf("ResolveAttestations failed: %v", err)
	}

	if len(resultFromBytes.Packages) != len(resultFromParsed.Packages) {
		t.Errorf("package count mismatch: Resolve=%d vs ResolveAttestations=%d",
			len(resultFromBytes.Packages), len(resultFromParsed.Packages))
	}
	if len(resultFromBytes.Files) != len(resultFromParsed.Files) {
		t.Errorf("file count mismatch: Resolve=%d vs ResolveAttestations=%d",
			len(resultFromBytes.Files), len(resultFromParsed.Files))
	}
}

func BenchmarkResolve(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "python-rioxarray.json"))
	if err != nil {
		b.Fatalf("failed to read test attestation: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Resolve(data, Options{})
		if err != nil {
			b.Fatalf("Resolve failed: %v", err)
		}
	}
}

func TestResolveWithExcludePaths(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "python-rioxarray.json"))
	if err != nil {
		t.Fatalf("failed to read test attestation: %v", err)
	}

	// Resolve without excludes
	resultAll, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	// Resolve with a glob that excludes python site-packages
	resultExcluded, err := Resolve(data, Options{
		ExcludePaths: []string{"*site-packages*"},
	})
	if err != nil {
		t.Fatalf("Resolve with excludes returned error: %v", err)
	}

	// The excluded result should have <= packages than the full one
	if len(resultExcluded.Packages) > len(resultAll.Packages) {
		t.Errorf("excluding paths should not produce more packages: %d vs %d",
			len(resultExcluded.Packages), len(resultAll.Packages))
	}
}

func TestResolveEmptyInput(t *testing.T) {
	// Resolve with valid but empty attestation data should not error
	emptyStatement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://witness.testifysec.com/attestation-collection/v0.1","subject":[],"predicate":{"name":"empty","attestations":[]}}`)

	result, err := Resolve(emptyStatement, Options{})
	if err != nil {
		t.Fatalf("Resolve empty attestation returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for empty attestation")
	}
	if len(result.Packages) != 0 {
		t.Errorf("expected 0 packages for empty attestation, got %d", len(result.Packages))
	}
}

func TestUnownedFiles(t *testing.T) {
	r := &Result{
		Files: []File{
			{Path: "/a"},
			{Path: "/b"},
			{Path: "/c"},
		},
		Relationships: []Relationship{
			{Type: Contains, FromPackageID: "p1", ToPath: "/b"},
		},
	}

	unowned := r.UnownedFiles()
	if len(unowned) != 2 {
		t.Fatalf("expected 2 unowned files, got %d", len(unowned))
	}
	if unowned[0].Path != "/a" || unowned[1].Path != "/c" {
		t.Errorf("unexpected unowned files: %v", unowned)
	}
}

func TestPackageByID(t *testing.T) {
	r := &Result{
		Packages: []Package{
			{ID: "abc", Name: "foo"},
			{ID: "def", Name: "bar"},
		},
	}

	pkg, ok := r.PackageByID("def")
	if !ok {
		t.Fatal("expected to find package with ID def")
	}
	if pkg.Name != "bar" {
		t.Errorf("expected Name bar, got %s", pkg.Name)
	}

	_, ok = r.PackageByID("nonexistent")
	if ok {
		t.Fatal("expected not to find nonexistent package")
	}
}

// Output digests are sorted copies, so a caller mutating a result cannot reach
// back into the resolvers, and two runs order them identically.
func TestCopyDigestsSortsAndCopies(t *testing.T) {
	in := []Digest{{Algorithm: "sha512", Value: "ccc"}, {Algorithm: "sha1", Value: "aaa"}, {Algorithm: "sha256", Value: "bbb"}}
	out := copyDigests(in)

	if out[0].Algorithm != "sha1" || out[1].Algorithm != "sha256" || out[2].Algorithm != "sha512" {
		t.Fatalf("expected sorted by algorithm, got %v", out)
	}
	out[0].Value = "changed"
	if in[1].Value != "aaa" {
		t.Fatal("copyDigests must not share the input slice")
	}
	if copyDigests(nil) != nil {
		t.Fatal("expected nil for no digests")
	}
}

// A full, undistilled attestation (orjson: a maturin build, pip plus cargo),
// for behaviour at scale.
func TestResolveOrjsonWitness(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "orjson_witness.json"))
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	result, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if got := len(result.Packages); got != 89 {
		t.Errorf("expected 89 packages, got %d", got)
	}
	if got := len(result.Files); got != 10835 {
		t.Errorf("expected 10835 files, got %d", got)
	}
	if got := len(result.UnownedFiles()); got != 1554 {
		t.Errorf("expected 1554 unowned files, got %d", got)
	}

	var withDigest int
	for _, f := range result.Files {
		if len(f.Digests) > 0 {
			withDigest++
		}
	}
	if withDigest != 4812 {
		t.Errorf("expected 4812 files with a digest, got %d", withDigest)
	}

	// 44 staged wheels and 38 crates, all verified against PyPI and crates.io.
	var withPackageDigest int
	for _, p := range result.Packages {
		if len(p.Digests) > 0 {
			withPackageDigest++
		}
	}
	if withPackageDigest != 82 {
		t.Errorf("expected 82 packages to claim a digest, got %d", withPackageDigest)
	}
}

// OmitOwnedFiles leaves exactly the paths no package claimed.
func TestResolveOmitOwnedFiles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "python-rioxarray.json"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	full, err := Resolve(data, Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	lean, err := Resolve(data, Options{OmitOwnedFiles: true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	unowned := full.UnownedFiles()
	if len(unowned) == 0 || len(unowned) == len(full.Files) {
		t.Fatalf("the sample needs both owned and unowned files, got %d of %d", len(unowned), len(full.Files))
	}
	if len(lean.Files) != len(unowned) {
		t.Errorf("OmitOwnedFiles: got %d files, want the %d unowned", len(lean.Files), len(unowned))
	}
}

// A package seen on disk and downloaded, and one only downloaded.
const pathAndNetworkAttestation = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
  "predicate": {
    "name": "build",
    "attestations": [
      {
        "type": "https://witness.dev/attestations/command-run/v0.1",
        "attestation": {
          "processes": [
            {
              "openedfiles": {
                "/app/node_modules/.pnpm/semver@7.8.5/node_modules/semver/package.json": {"sha256": "aaa"},
                "/app/node_modules/.pnpm/semver@7.8.5/node_modules/semver/index.js": {"sha256": "bbb"}
              }
            }
          ]
        }
      },
      {
        "type": "https://witness.dev/attestations/network-trace/v0.1",
        "attestation": {
          "network_trace": {
            "connections": [
              {
                "protocol": "https",
                "destination": {"hostname": "registry.npmjs.org", "ip": "104.16.6.34"},
                "http_exchanges": [
                  {
                    "request": {"method": "GET", "url": "https://registry.npmjs.org/semver/-/semver-7.8.5.tgz",
                                "headers": {"User-Agent": ["pnpm/10.34.6 npm/? node/v24.21.0 linux x64"]}},
                    "response": {"status_code": 200, "body": {"hash": "semver-archive-digest"}}
                  },
                  {
                    "request": {"method": "GET", "url": "https://registry.npmjs.org/yallist/-/yallist-4.0.0.tgz",
                                "headers": {"User-Agent": ["pnpm/10.34.6 npm/? node/v24.21.0 linux x64"]}},
                    "response": {"status_code": 200, "body": {"hash": "yallist-archive-digest"}}
                  }
                ]
              }
            ]
          }
        }
      }
    ]
  }
}`

// Path and network evidence for one PURL merge; download-only packages are
// still reported.
func TestResolveReportsPathAndNetworkEvidenceTogether(t *testing.T) {
	result, err := Resolve([]byte(pathAndNetworkAttestation), Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	byPURL := make(map[string]Package, len(result.Packages))
	for _, p := range result.Packages {
		byPURL[p.PURL] = p
	}
	if len(byPURL) != 2 {
		t.Fatalf("expected semver and yallist, got %v", purlsOf(result))
	}

	semver := byPURL["pkg:npm/semver@7.8.5"]
	if len(semver.Evidence) != 2 {
		t.Fatalf("semver should have one path and one network evidence, got %+v", semver.Evidence)
	}
	path, net := semver.Evidence[0], semver.Evidence[1]
	if path.Source != SourcePath || path.PkgMgr != "pnpm" || !strings.HasSuffix(path.Location, "/package.json") {
		t.Errorf("semver should cite its package.json from the pnpm store, got %+v", path)
	}
	if net.Source != SourceNetwork || net.PkgMgr != "pnpm" || !net.Artifact ||
		len(net.Digests) != 1 || net.Digests[0].Value != "semver-archive-digest" {
		t.Errorf("semver's download should be its artifact, by pnpm, with its body digest, got %+v", net)
	}

	// npm publishes sha512, not the sha256 a network trace records, so no
	// package digest is claimed — the download's digest stays on its evidence.
	if len(semver.Digests) != 0 {
		t.Errorf("an npm package claims no digest, got %v", semver.Digests)
	}

	yallist := byPURL["pkg:npm/yallist@4.0.0"]
	if len(yallist.Evidence) != 1 || yallist.Evidence[0].Source != SourceNetwork {
		t.Errorf("yallist rests on its download alone, got %+v", yallist.Evidence)
	}

	var semverFiles, yallistFiles int
	for _, rel := range result.Relationships {
		switch rel.FromPackageID {
		case semver.ID:
			semverFiles++
		case yallist.ID:
			yallistFiles++
		}
	}
	if semverFiles != 2 || yallistFiles != 0 {
		t.Errorf("semver should own both observed files and yallist none, got %d and %d", semverFiles, yallistFiles)
	}
}

// npm's flat node_modules has no versions, so downloads are the only evidence.
const networkOnlyAttestation = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
  "predicate": {
    "name": "build",
    "attestations": [
      {
        "type": "https://witness.dev/attestations/command-run/v0.1",
        "attestation": {
          "processes": [
            {
              "openedfiles": {
                "/app/node_modules/semver/index.js": {"sha256": "aaa"},
                "/app/node_modules/yallist/index.js": {"sha256": "bbb"}
              }
            }
          ]
        }
      },
      {
        "type": "https://witness.dev/attestations/network-trace/v0.1",
        "attestation": {
          "network_trace": {
            "connections": [
              {
                "protocol": "https",
                "destination": {"hostname": "registry.npmjs.org"},
                "http_exchanges": [
                  {
                    "request": {"method": "GET", "url": "https://registry.npmjs.org/semver/-/semver-7.8.5.tgz",
                                "headers": {"User-Agent": ["npm/10.9.0 node/v22.11.0 linux x64"]}},
                    "response": {"status_code": 200, "body": {"hash": "semver-archive-digest"}}
                  },
                  {
                    "request": {"method": "GET", "url": "https://registry.npmjs.org/yallist/-/yallist-4.0.0.tgz",
                                "headers": {"User-Agent": ["npm/10.9.0 node/v22.11.0 linux x64"]}},
                    "response": {"status_code": 200, "body": {"hash": "yallist-archive-digest"}}
                  }
                ]
              }
            ]
          }
        }
      }
    ]
  }
}`

func TestResolveReportsDownloadOnlyPackages(t *testing.T) {
	result, err := Resolve([]byte(networkOnlyAttestation), Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	got := make([]string, 0, len(result.Packages))
	for _, p := range result.Packages {
		got = append(got, p.PURL)
	}
	sort.Strings(got)

	want := []string{"pkg:npm/semver@7.8.5", "pkg:npm/yallist@4.0.0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("a flat node_modules yields no versions, so both packages must come "+
			"from the downloads\n  want: %v\n  got:  %v", want, got)
	}

	for _, p := range result.Packages {
		if len(p.Evidence) != 1 {
			t.Fatalf("%s should rest on its download alone, got %+v", p.PURL, p.Evidence)
		}
		e := p.Evidence[0]
		if e.Source != SourceNetwork || e.PkgMgr != "npm" || !e.Artifact || len(e.Digests) != 1 {
			t.Errorf("%s: expected npm's artifact download with its digest, got %+v", p.PURL, e)
		}
	}

	// The flat paths are still reported as files; they just own nothing,
	// because no version can be attached to them.
	if len(result.Relationships) != 0 {
		t.Errorf("expected no ownership, got %d relationships", len(result.Relationships))
	}
	if len(result.Files) != 2 {
		t.Errorf("expected both flat paths as files, got %d", len(result.Files))
	}
}

// Dropping network-trace from the types must drop the download-only package
// and the network evidence, leaving exactly what paths establish on their own.
func TestResolveWithoutNetworkType(t *testing.T) {
	result, err := Resolve([]byte(pathAndNetworkAttestation), Options{
		AttestationTypes: []string{"material", "command-run", "product"},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(result.Packages) != 1 {
		t.Fatalf("expected only the path-derived package, got %d", len(result.Packages))
	}
	if result.Packages[0].PURL != "pkg:npm/semver@7.8.5" {
		t.Fatalf("unexpected package: %s", result.Packages[0].PURL)
	}
	for _, e := range result.Packages[0].Evidence {
		if e.Source != SourcePath {
			t.Errorf("without the network trace there is no network evidence, got %+v", e)
		}
	}
}

// Only ecosystems whose registry publishes the artifact's sha256 claim a
// package digest; others keep the artifact digest on its evidence.
func TestResolveClaimsDigestOnlyWhereTheRegistryPublishesSHA256(t *testing.T) {
	const crate = "/cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/anstream-0.6.17.crate"
	const module = "/go/pkg/mod/cache/download/github.com/lib/pq/@v/v1.11.1.zip"

	result, err := ResolveAttestations([]attestation.TypedAttestation{{
		Type: "command-run",
		Data: map[string]interface{}{"processes": []interface{}{map[string]interface{}{
			"openedfiles": map[string]interface{}{
				crate:  map[string]interface{}{"sha256": "23a1e53f0f5d86382dafe1cf314783b2044280f406e7e1506368220ad11b1338"},
				module: map[string]interface{}{"sha256": "zip-digest"},
			},
		}}},
	}}, Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	byPURL := map[string]Package{}
	for _, p := range result.Packages {
		byPURL[p.PURL] = p
	}

	// crates.io's index records cksum 23a1e53f… for anstream 0.6.17.
	cargo := byPURL["pkg:cargo/anstream@0.6.17"]
	if len(cargo.Digests) != 1 || cargo.Digests[0].Value != "23a1e53f0f5d86382dafe1cf314783b2044280f406e7e1506368220ad11b1338" {
		t.Errorf("a .crate's sha256 is what crates.io publishes, got %v", cargo.Digests)
	}

	golang := byPURL["pkg:golang/github.com/lib/pq@v1.11.1"]
	if len(golang.Digests) != 0 {
		t.Errorf("a Go module claims no package digest, got %v", golang.Digests)
	}
	if len(golang.Evidence) != 1 || !golang.Evidence[0].Artifact || len(golang.Evidence[0].Digests) != 1 {
		t.Errorf("the zip's digest must stay on its evidence, got %+v", golang.Evidence)
	}
}

// Two artifact digests that disagree mean one of them is not the artifact the
// registry published, with no telling which, so neither is claimed.
func TestResolveWithholdsTheDigestWhenArtifactsDisagree(t *testing.T) {
	const crate = "/cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/anstream-0.6.17.crate"

	result, err := ResolveAttestations([]attestation.TypedAttestation{
		{Type: "command-run", Data: map[string]interface{}{"processes": []interface{}{map[string]interface{}{
			"openedfiles": map[string]interface{}{crate: map[string]interface{}{"sha256": "path-digest"}},
		}}}},
		{Type: "network-trace", Data: map[string]interface{}{"network_trace": map[string]interface{}{
			"connections": []interface{}{map[string]interface{}{
				"destination": map[string]interface{}{"hostname": "static.crates.io"},
				"http_exchanges": []interface{}{map[string]interface{}{
					"request":  map[string]interface{}{"url": "https://static.crates.io/crates/anstream/0.6.17/download"},
					"response": map[string]interface{}{"status_code": 200.0, "body": map[string]interface{}{"hash": "network-digest"}},
				}},
			}},
		}}},
	}, Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(result.Packages) != 1 {
		t.Fatalf("expected one package, got %v", purlsOf(result))
	}
	if d := result.Packages[0].Digests; len(d) != 0 {
		t.Errorf("conflicting artifact digests must not be claimed, got %v", d)
	}
	if n := len(result.Packages[0].Evidence); n != 2 {
		t.Errorf("both observations must still be reported, got %d", n)
	}
}

// citations returns the paths that identified a package: its evident-by
// relationships.
func citations(result *Result, p Package) []string {
	var out []string
	for _, rel := range result.Relationships {
		if rel.FromPackageID == p.ID && rel.Type == EvidentBy {
			out = append(out, rel.ToPath)
		}
	}
	return out
}

func purlsOf(result *Result) []string {
	out := make([]string, 0, len(result.Packages))
	for _, p := range result.Packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

// A +incompatible module seen on disk and downloaded is one package.
func TestResolveMergesAnIncompatibleGoModuleAcrossSources(t *testing.T) {
	const zip = "/go/pkg/mod/cache/download/github.com/docker/docker/@v/v20.10.7+incompatible.zip"

	result, err := ResolveAttestations([]attestation.TypedAttestation{
		{Type: "command-run", Data: map[string]interface{}{"processes": []interface{}{map[string]interface{}{
			"openedfiles": map[string]interface{}{zip: map[string]interface{}{"sha256": "zip-digest"}},
		}}}},
		{Type: "network-trace", Data: map[string]interface{}{"network_trace": map[string]interface{}{
			"connections": []interface{}{map[string]interface{}{
				"destination": map[string]interface{}{"hostname": "proxy.golang.org"},
				"http_exchanges": []interface{}{map[string]interface{}{
					"request":  map[string]interface{}{"url": "https://proxy.golang.org/github.com/docker/docker/@v/v20.10.7+incompatible.zip"},
					"response": map[string]interface{}{"status_code": 200.0, "body": map[string]interface{}{"hash": "zip-digest"}},
				}},
			}},
		}}},
	}, Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if got := purlsOf(result); len(got) != 1 || got[0] != "pkg:golang/github.com/docker/docker@v20.10.7%2Bincompatible" {
		t.Fatalf("expected one module, got %v", got)
	}
	if n := len(result.Packages[0].Evidence); n != 2 {
		t.Fatalf("expected path and network evidence on the one package, got %d", n)
	}
}
