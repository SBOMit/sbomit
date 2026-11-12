package resolve

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sbomit/sbomit/pkg/hashlookup"
	"github.com/sbomit/sbomit/pkg/resolver"
)

const (
	shaLibc  = "1111111111111111111111111111111111111111111111111111111111111111"
	shaFFI   = "2222222222222222222222222222222222222222222222222222222222222222"
	shaPyc   = "3333333333333333333333333333333333333333333333333333333333333333"
	shaWork  = "4444444444444444444444444444444444444444444444444444444444444444"
	shaMeta  = "5555555555555555555555555555555555555555555555555555555555555555"
	shaPipPy = "6666666666666666666666666666666666666666666666666666666666666666"
)

// System files a build opened, plus a workspace file and a site-packages
// file that the python resolver claims by path. (sbomit's noise filter drops
// __pycache__/*.pyc before any resolver, so they are never sent.)
const systemFilesAttestation = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
  "predicate": {"name": "build", "attestations": [{
    "type": "https://witness.dev/attestations/command-run/v0.1",
    "attestation": {"processes": [{"openedfiles": {
      "/lib/aarch64-linux-gnu/libc.so.6": {"sha256": "` + shaLibc + `"},
      "/usr/lib/aarch64-linux-gnu/../aarch64-linux-gnu/libffi.so.8": {"sha256": "` + shaFFI + `"},
      "/usr/lib/python3.12/__pycache__/abc.cpython-312.pyc": {"sha256": "` + shaPyc + `"},
      "/usr/lib/python3/dist-packages/pip/__init__.py": {"sha256": "` + shaPipPy + `"},
      "/home/runner/work/app/main.c": {"sha256": "` + shaWork + `"},
      "/usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA": {"sha256": "` + shaMeta + `"}
    }}]}
  }]}
}`

// fakeAttributor records what it was sent and answers with fixed packages.
type fakeAttributor struct {
	sent []hashlookup.File
	res  *hashlookup.Result
	err  error
}

func (f *fakeAttributor) Attribute(_ context.Context, files []hashlookup.File) (*hashlookup.Result, error) {
	f.sent = files
	return f.res, f.err
}

func TestResolveHashLookup(t *testing.T) {
	fake := &fakeAttributor{res: &hashlookup.Result{Distro: "ubuntu", Suite: "noble", Arch: "arm64", Packages: []hashlookup.Package{
		{Name: "libc6", Exact: true, Versions: []string{"2.39-0ubuntu8.6"},
			PURL:  "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.6?arch=arm64&upstream=glibc&distro=ubuntu-24.04",
			Files: []hashlookup.Match{{Path: "/lib/aarch64-linux-gnu/libc.so.6", Evidence: hashlookup.EvidenceHash}}},
		{Name: "libffi8", Exact: true, Versions: []string{"3.4.6-1build1"},
			PURL:  "pkg:deb/ubuntu/libffi8@3.4.6-1build1?arch=arm64&upstream=libffi&distro=ubuntu-24.04",
			Files: []hashlookup.Match{{Path: "/usr/lib/aarch64-linux-gnu/libffi.so.8", Evidence: hashlookup.EvidenceHash}}},
		// Ambiguous version: kept, without a version.
		{Name: "python3-pip", Exact: false, Versions: []string{"24.0+dfsg-1ubuntu1", "24.0+dfsg-1ubuntu1.3"},
			PURL:  "pkg:deb/ubuntu/python3-pip?arch=all&distro=ubuntu-24.04",
			Files: []hashlookup.Match{{Path: "/usr/lib/python3/dist-packages/pip/__init__.py", Evidence: hashlookup.EvidenceHash}}},
		// A misbehaving service must not claim a path it was not sent.
		{Name: "rogue", Exact: true, Versions: []string{"1"}, PURL: "pkg:deb/ubuntu/rogue@1",
			Files: []hashlookup.Match{{Path: "/home/runner/work/app/main.c", Evidence: hashlookup.EvidenceHash}}},
	}}}

	result, err := Resolve([]byte(systemFilesAttestation), Options{HashLookup: fake})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}

	// Sent: system files only; not the workspace file, not the file the
	// python resolver already claimed; paths cleaned.
	sent := map[string]bool{}
	for _, f := range fake.sent {
		sent[f.Path] = true
	}
	for _, p := range []string{"/lib/aarch64-linux-gnu/libc.so.6", "/usr/lib/aarch64-linux-gnu/libffi.so.8",
		"/usr/lib/python3/dist-packages/pip/__init__.py"} {
		if !sent[p] {
			t.Errorf("%s should have been sent; sent %v", p, fake.sent)
		}
	}
	for _, p := range []string{"/home/runner/work/app/main.c", "/usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA",
		"/usr/lib/python3.12/__pycache__/abc.cpython-312.pyc"} {
		if sent[p] {
			t.Errorf("%s must not be sent", p)
		}
	}

	byPURL := map[string]Package{}
	for _, p := range result.Packages {
		byPURL[p.PURL] = p
	}
	libc := byPURL["pkg:deb/ubuntu/libc6@2.39-0ubuntu8.6?arch=arm64&upstream=glibc&distro=ubuntu-24.04"]
	if libc.Ecosystem != "deb" || libc.Version != "2.39-0ubuntu8.6" || len(libc.Evidence) != 1 ||
		libc.Evidence[0].Source != SourceHash || libc.Evidence[0].PkgMgr != "dpkg" ||
		len(libc.Evidence[0].Digests) != 1 || libc.Evidence[0].Digests[0].Value != shaLibc {
		t.Fatalf("libc6 = %+v", libc)
	}
	if len(libc.Files) != 1 || libc.Files[0].Path != "/lib/aarch64-linux-gnu/libc.so.6" {
		t.Fatalf("libc6 should own libc.so.6: %+v", libc.Files)
	}
	// The attested (uncleaned) spelling is what the package owns.
	ffi := byPURL["pkg:deb/ubuntu/libffi8@3.4.6-1build1?arch=arm64&upstream=libffi&distro=ubuntu-24.04"]
	if len(ffi.Files) != 1 || !strings.Contains(ffi.Files[0].Path, "/../") {
		t.Fatalf("libffi8 should own the attested path: %+v", ffi.Files)
	}
	pip := byPURL["pkg:deb/ubuntu/python3-pip?arch=all&distro=ubuntu-24.04"]
	if pip.Name != "python3-pip" || pip.Version != "" || len(pip.Files) != 1 {
		t.Fatalf("ambiguous pip should be kept without a version: %+v", pip)
	}
	if _, ok := byPURL["pkg:deb/ubuntu/rogue@1"]; ok {
		t.Fatal("a package claiming only unsent paths must be dropped")
	}

	// Unclaimed: the workspace file only (requests is claimed by path).
	if len(result.Files) != 1 || result.Files[0].Path != "/home/runner/work/app/main.c" {
		t.Fatalf("unclaimed = %+v", result.Files)
	}
}

func TestResolveHashLookupFailureLeavesFilesUnclaimed(t *testing.T) {
	fake := &fakeAttributor{err: errors.New("connection refused")}
	result, err := Resolve([]byte(systemFilesAttestation), Options{HashLookup: fake})
	if err != nil {
		t.Fatalf("a lookup failure must not fail resolution: %v", err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "connection refused") {
		t.Fatalf("warnings = %v", result.Warnings)
	}
	for _, p := range result.Packages {
		if p.Ecosystem == "deb" {
			t.Fatalf("no deb packages expected, got %s", p.PURL)
		}
	}
	if len(result.Files) != 4 { // all but requests METADATA (path-claimed) and the .pyc (noise)
		t.Fatalf("all system files should stay unclaimed, got %d: %+v", len(result.Files), result.Files)
	}
}

func TestResolveWithoutHashLookupSendsNothing(t *testing.T) {
	result, err := Resolve([]byte(systemFilesAttestation), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range result.Packages {
		if p.Ecosystem == "deb" {
			t.Fatalf("hash lookup is opt-in; got %s", p.PURL)
		}
	}
}

// The service may also assign generated .pyc files (via the .py source the
// package ships). sbomit's noise filter normally drops them first, but if
// one reaches the hash pass it is claimed with path evidence.
func TestAttributeByHashPycIsPathEvidence(t *testing.T) {
	pyc := "/usr/lib/python3.12/__pycache__/abc.cpython-312.pyc"
	fake := &fakeAttributor{res: &hashlookup.Result{Packages: []hashlookup.Package{{
		Name: "libpython3.12-stdlib", Exact: true, Versions: []string{"3.12.3-1ubuntu0.8"},
		PURL:  "pkg:deb/ubuntu/libpython3.12-stdlib@3.12.3-1ubuntu0.8",
		Files: []hashlookup.Match{{Path: pyc, Evidence: hashlookup.EvidencePycSource}},
	}}}}
	files := []resolver.FileInfo{{Path: pyc, Digests: []Digest{{Algorithm: "sha256", Value: shaPyc}}}}
	hashed, remaining, warnings := attributeByHash(Options{HashLookup: fake}, files)
	if len(warnings) != 0 || len(remaining) != 0 || len(hashed) != 1 || hashed[0].matches[0].source != SourcePath {
		t.Fatalf("hashed=%+v remaining=%+v warnings=%v", hashed, remaining, warnings)
	}
}
