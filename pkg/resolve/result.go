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

import "github.com/sbomit/sbomit/pkg/attestation"

// Result is what resolving an attestation yields.
type Result struct {
	Packages []Package

	// Files are the attested paths no package claimed. A package's own files
	// are in [Package.Files].
	Files []File

	// Warnings are problems that did not stop resolution, such as an
	// unreachable hash lookup service.
	Warnings []string
}

// Package is one package the attestation shows, from paths, requests, or both.
type Package struct {
	Name    string
	Version string

	// Ecosystem is the PURL type: pypi, conda, golang, cargo, npm, maven,
	// or deb for OS packages found by hash lookup.
	Ecosystem string

	// PURL identifies the package; a Result has one Package per PURL.
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

	// Files are the paths the package owns, including its path evidence.
	Files []File
}

// Source says where a piece of evidence came from.
type Source string

const (
	// SourcePath is an attested path (material, command-run or product).
	SourcePath Source = "path"

	// SourceNetwork is a request in a network-trace attestation.
	SourceNetwork Source = "network"

	// SourceHash is an attested file whose sha256 a hash lookup service
	// found in the package (see [Options.HashLookup]).
	SourceHash Source = "hash"
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
