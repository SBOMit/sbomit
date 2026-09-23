// Package resolve turns a witness attestation into the packages and files it
// describes.
//
// Given a witness attestation recording what a build actually touched, it
// returns which packages were used and which files no package accounts for.
//
//	bundle, _ := os.ReadFile("attestation.json")
//	result, err := resolve.Resolve(bundle, resolve.Options{})
//	for _, p := range result.Packages {
//	    fmt.Println(p.PURL, "evidenced by", p.Locations[0])
//	}
//
// Resolve accepts a bare in-toto statement or a DSSE envelope. For finer
// control, call [attestation.ParseWitnessData] and pass the result to
// [ResolveAttestations].
package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Result is what resolving an attestation yields.
type Result struct {
	Packages []Package

	// Files are the attested paths that no package claimed. Files belonging to
	// a package are deliberately absent — they are represented by
	// Relationships instead, so a package and its contents are not reported
	// twice. [Options.IncludeOwnedFiles] includes them here too.
	Files []File

	// Relationships map packages to the paths they own.
	Relationships []Relationship
}

// Package is a package derived from paths observed during the build.
type Package struct {
	// ID is stable across runs for the same package identity and is what
	// [Relationship.FromPackageID] refers to. Treat it as opaque.
	ID string

	Name    string
	Version string

	// Ecosystem is one of: pypi, golang, cargo, npm, maven.
	Ecosystem string

	PURL string

	// Locations are the attested paths that evidenced this package, not the
	// full set of files it owns. Ownership is in Relationships.
	Locations []string

	// Digests of the package's distributed artifact. Path resolution cannot
	// establish this, so it is empty until network attestations contribute.
	Digests []Digest

	// FoundBy names the resolver that derived this package.
	FoundBy string

	// DownloadURL is the URL from which the package was downloaded, set by
	// network resolvers when available.
	DownloadURL string

	// DownloadIP is the IP address from which the package was downloaded,
	// set by network resolvers when available.
	DownloadIP string
}

// File is an attested path with whatever digests the attestation recorded.
// Digests may be empty; witness records some opened files without one.
type File struct {
	Path    string
	Digests []Digest
}

// Digest is a hash algorithm and its hex-encoded value.
type Digest struct {
	Algorithm string
	Value     string
}

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

// UnownedFiles returns the files no package claimed. With the default options
// this is the same as Files; with [Options.IncludeOwnedFiles] it filters back
// down.
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

// digestsOf converts an algorithm->hex map into a sorted Digest slice so that
// output ordering is stable.
func digestsOf(m map[string]string) []Digest {
	if len(m) == 0 {
		return nil
	}

	algos := make([]string, 0, len(m))
	for algo := range m {
		algos = append(algos, algo)
	}
	sort.Strings(algos)

	out := make([]Digest, 0, len(algos))
	for _, algo := range algos {
		out = append(out, Digest{Algorithm: algo, Value: m[algo]})
	}
	return out
}
