// Package resolve turns a witness attestation into the packages and files it
// describes.
//
// Given a witness attestation recording what a build actually touched, it
// returns which packages were used, which files belong to them, and which
// files no package accounts for.
//
//	bundle, _ := os.ReadFile("attestation.json")
//	result, err := resolve.Resolve(bundle, resolve.Options{})
//	for _, p := range result.Packages {
//	    for _, e := range p.Evidence {
//	        fmt.Println(p.PURL, e.Source, e.PkgMgr, e.Location)
//	    }
//	}
//
// Packages are identified from attested paths (site-packages/werkzeug-3.0.1.dist-info
// means werkzeug 3.0.1) and from network-trace request URLs. Both are
// reported, each as [Evidence] naming its source and package manager; how to
// weigh them is left to the caller.
//
// Resolve accepts a bare in-toto statement or a DSSE envelope. For finer
// control, call [attestation.ParseWitnessData] and pass the result to
// [ResolveAttestations].
package resolve

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/sbomit/sbomit/pkg/attestation"
)

// Result is what resolving an attestation yields.
type Result struct {
	Packages []Package

	// Files are the attested paths, both those belonging to a package and
	// those no package claimed. Ownership is in Relationships rather than
	// implied by presence here.
	// [Options.OmitOwnedFiles] narrows this to just the unclaimed paths
	// [Result.UnownedFiles] does the same after.
	Files []File

	// Relationships map packages to the paths they own.
	Relationships []Relationship
}

// Package is one package the attestation shows, from paths, requests, or both.
type Package struct {
	// ID is stable across runs for the same package identity and is what
	// [Relationship.FromPackageID] refers to. Treat it as opaque.
	ID string

	Name    string
	Version string

	// Ecosystem is the PURL type: pypi, conda, golang, cargo, npm, maven.
	Ecosystem string

	PURL string

	// Evidence is every path and request the package was identified from,
	// plus its artifact file. A package seen only in the network trace has no
	// path evidence and owns no files.
	Evidence []Evidence

	// Digests is the sha256 of the package's artifact, set only for pypi, cargo
	// and conda (whose registries publish that value) and only when all
	// artifact evidence agrees. Other ecosystems' artifact hashes stay on
	// Evidence.
	Digests []Digest
}

// Source says where a piece of evidence came from.
type Source string

const (
	// SourcePath is an attested path (material, command-run or product).
	SourcePath Source = "path"

	// SourceNetwork is a request in a network-trace attestation.
	SourceNetwork Source = "network"
)

// Evidence is one observation a package rests on.
type Evidence struct {
	Source Source

	// PkgMgr is the package manager: the one whose paths these are, or the
	// one named in the request's User-Agent. Empty when unknown.
	PkgMgr string

	// Location is the attested path, or the request URL.
	Location string

	// Artifact reports whether Location is the artifact the registry publishes
	// (not a file inside it, metadata, or a yarn cache zip).
	Artifact bool

	// Digests recorded for Location: the file's, or the response body's.
	Digests []Digest
}

// File is an attested path with every distinct digest recorded for it. There
// may be none, or two for one algorithm if the file changed during the build.
type File struct {
	Path    string
	Digests []Digest
}

// Digest is a hash algorithm and its hex-encoded value.
type Digest = attestation.Digest

// RelationshipType describes how a package relates to a path.
type RelationshipType string

const (
	// Contains means the package owns the file at ToPath.
	Contains RelationshipType = "contains"

	// EvidentBy means the file at ToPath is what identified the package. Every
	// EvidentBy path is also contained by the package.
	EvidentBy RelationshipType = "evident-by"
)

// Relationship links a package to a path.
//
// ToPath is a path rather than a reference to a File because owned files are
// not emitted as file nodes by default, so it will typically name a path with
// no entry in [Result.Files].
type Relationship struct {
	Type          RelationshipType
	FromPackageID string
	ToPath        string
}

// UnownedFiles returns the files no package claimed
func (r *Result) UnownedFiles() []File {
	owned := make(map[string]struct{}, len(r.Relationships))
	for _, rel := range r.Relationships {
		owned[rel.ToPath] = struct{}{}
	}

	out := make([]File, 0, len(r.Files))
	for _, f := range r.Files {
		if _, ok := owned[f.Path]; ok {
			continue
		}
		out = append(out, f)
	}
	return out
}

// PackageByID returns the package with the given ID, or false if none.
func (r *Result) PackageByID(id string) (Package, bool) {
	for _, p := range r.Packages {
		if p.ID == id {
			return p, true
		}
	}
	return Package{}, false
}

// packageID derives a stable identifier from a package's identity. It must be
// deterministic across runs, since consumers may persist or diff results.
func packageID(purl string) string {
	sum := sha256.Sum256([]byte(purl))
	return hex.EncodeToString(sum[:8])
}
