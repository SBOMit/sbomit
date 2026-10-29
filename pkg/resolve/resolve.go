package resolve

import (
	"path/filepath"
	"slices"
	"sort"

	"github.com/sbomit/sbomit/pkg/attestation"
	"github.com/sbomit/sbomit/pkg/resolver"
	"github.com/sbomit/sbomit/pkg/resolver/network"
)

// Resolve parses a witness attestation bundle (bare in-toto statement or DSSE
// envelope) and derives the packages and files it describes.
func Resolve(data []byte, opts Options) (*Result, error) {
	attestations, err := attestation.ParseWitnessData(data, opts.attestationTypes())
	if err != nil {
		return nil, err
	}
	return ResolveAttestations(attestations, opts)
}

// ResolveAttestations derives packages and files from already-parsed
// attestations, avoiding a re-parse when the caller needs the attestations
// for other purposes.
func ResolveAttestations(attestations []attestation.TypedAttestation, opts Options) (*Result, error) {
	if len(attestations) == 0 {
		return &Result{}, nil
	}

	// Extract files from attestations.
	attFiles := attestation.ExtractFilesFromAttestations(attestations, opts.attestationTypes())

	// Convert to resolver.FileInfo, applying user-level exclude globs.
	var files []resolver.FileInfo
	for _, f := range attFiles {
		if shouldExclude(f.Path, opts.ExcludePaths) {
			continue
		}
		files = append(files, resolver.FileInfo{Path: f.Path, Digests: f.Digests})
	}

	// Run through the ecosystem resolver chain (python, go, rust, js, maven).
	resolved := resolver.NewResolverChain().ResolveAll(files)

	// Requests the build made. Reported alongside paths; weighing them is the
	// caller's decision.
	downloads := network.NewChain().ResolveAll(network.ExtractConnections(attestations))

	return assemble(resolved, files, downloads, opts), nil
}

// assemble builds the public Result: one Package per PURL with evidence from
// paths and requests, plus files and their ownership.
func assemble(resolved resolver.ResolverResult, observed []resolver.FileInfo, downloads []network.Download, opts Options) *Result {
	out := &Result{}

	digestsByPath := make(map[string][]Digest, len(observed))
	for _, f := range observed {
		digestsByPath[f.Path] = f.Digests
	}

	index := make(map[string]int)
	add := func(info resolver.PackageInfo, ev []Evidence) {
		if i, ok := index[info.PURL]; ok {
			out.Packages[i].Evidence = append(out.Packages[i].Evidence, ev...)
			return
		}
		index[info.PURL] = len(out.Packages)
		out.Packages = append(out.Packages, Package{
			ID:        packageID(info.PURL),
			Name:      info.Name,
			Version:   info.Version,
			Ecosystem: info.Ecosystem,
			PURL:      info.PURL,
			Evidence:  ev,
		})
	}

	for _, pkg := range resolved.Packages {
		add(pkg, pathEvidence(pkg, digestsByPath))
	}
	for _, d := range downloads {
		add(d.Package, []Evidence{{
			Source:   SourceNetwork,
			PkgMgr:   d.Package.PkgMgr,
			Location: d.URL,
			Artifact: d.Artifact,
			Digests:  copyDigests(d.Digests),
		}})
	}

	for i := range out.Packages {
		pkg := &out.Packages[i]
		sort.SliceStable(pkg.Evidence, func(a, b int) bool {
			ea, eb := pkg.Evidence[a], pkg.Evidence[b]
			if ea.Source != eb.Source {
				return ea.Source == SourcePath
			}
			return ea.Location < eb.Location
		})
		pkg.Digests = packageDigest(pkg.Ecosystem, pkg.Evidence)
	}

	idByPURL := make(map[string]string, len(out.Packages))
	for _, pkg := range out.Packages {
		idByPURL[pkg.PURL] = pkg.ID
	}

	// Cited paths become evident-by edges; other owned files, contains.
	evidence := make(map[string]struct{})
	for _, pkg := range resolved.Packages {
		for _, loc := range pkg.Locations {
			evidence[pkg.PURL+"\x00"+loc] = struct{}{}
		}
	}

	for _, owned := range resolved.Owned {
		id, ok := idByPURL[owned.OwnerPURL]
		if !ok {
			continue
		}

		relType := Contains
		if _, isEvidence := evidence[owned.OwnerPURL+"\x00"+owned.Path]; isEvidence {
			relType = EvidentBy
		}

		out.Relationships = append(out.Relationships, Relationship{
			Type:          relType,
			FromPackageID: id,
			ToPath:        owned.Path,
		})

		if !opts.OmitOwnedFiles {
			out.Files = append(out.Files, File{Path: owned.Path, Digests: copyDigests(owned.Digests)})
		}
	}

	// Files that no package claimed.
	for _, f := range resolved.Files {
		out.Files = append(out.Files, File{Path: f.Path, Digests: copyDigests(f.Digests)})
	}

	// Sorted for reproducible output; Relationships follow resolved.Owned,
	// which is already sorted.
	sort.Slice(out.Packages, func(i, j int) bool { return out.Packages[i].PURL < out.Packages[j].PURL })
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })

	return out
}

// pathEvidence is each cited path, plus the artifact if it is another file.
func pathEvidence(pkg resolver.PackageInfo, digestsByPath map[string][]Digest) []Evidence {
	var artifactPath string
	if pkg.Artifact != nil {
		artifactPath = pkg.Artifact.Path
	}

	var ev []Evidence
	for _, loc := range pkg.Locations {
		digests := digestsByPath[loc]
		if loc == artifactPath {
			// May include a digest read from the path (Gradle's sha1 directory).
			digests = pkg.Artifact.Digests
		}
		ev = append(ev, Evidence{
			Source:   SourcePath,
			PkgMgr:   pkg.PkgMgr,
			Location: loc,
			Artifact: loc == artifactPath,
			Digests:  copyDigests(digests),
		})
	}

	if pkg.Artifact != nil && !slices.Contains(pkg.Locations, artifactPath) {
		ev = append(ev, Evidence{
			Source:   SourcePath,
			PkgMgr:   pkg.PkgMgr,
			Location: artifactPath,
			Artifact: true,
			Digests:  copyDigests(pkg.Artifact.Digests),
		})
	}

	return ev
}

// TODO: comparableDigestEcosystems are those whose registry publishes the artifact's
// sha256. We could add more, but the others are not comparable because they don't publish the artifact's digest, or they publish a different one than the one we compute from the file.
var comparableDigestEcosystems = map[string]struct{}{
	"pypi":  {},
	"cargo": {},
	"conda": {},
}

// packageDigest returns the sha256 all artifact evidence agrees on, or nil if
// there is none, they disagree, or the ecosystem is not comparable.
func packageDigest(ecosystem string, evidence []Evidence) []Digest {
	if _, ok := comparableDigestEcosystems[ecosystem]; !ok {
		return nil
	}

	var value string
	for _, e := range evidence {
		if !e.Artifact {
			continue
		}
		for _, d := range e.Digests {
			if d.Algorithm != "sha256" {
				continue
			}
			if value != "" && value != d.Value {
				return nil
			}
			value = d.Value
		}
	}

	if value == "" {
		return nil
	}
	return []Digest{{Algorithm: "sha256", Value: value}}
}

// copyDigests returns a sorted copy.
func copyDigests(digests []Digest) []Digest {
	if len(digests) == 0 {
		return nil
	}
	out := append([]Digest(nil), digests...)
	attestation.SortDigests(out)
	return out
}

// shouldExclude returns true if the path matches any of the user's exclude globs.
func shouldExclude(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
	}
	return false
}
