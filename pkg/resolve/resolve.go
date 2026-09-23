package resolve

import (
	"path/filepath"
	"sort"

	"github.com/sbomit/sbomit/pkg/attestation"
	"github.com/sbomit/sbomit/pkg/resolver"
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
		files = append(files, resolver.FileInfo{
			Path:   f.Path,
			Hashes: f.Hashes,
		})
	}

	// Run through the ecosystem resolver chain (python, go, rust, js, maven).
	chain := resolver.NewResolverChain()
	resolved := chain.ResolveAll(files)

	return assemble(resolved, opts), nil
}

// assemble converts the internal resolver result into the public Result type,
// building containment and evidence relationships.
func assemble(resolved resolver.ResolverResult, opts Options) *Result {
	out := &Result{}

	idByPURL := make(map[string]string, len(resolved.Packages))
	for _, pkg := range resolved.Packages {
		id := packageID(pkg.PURL)
		idByPURL[pkg.PURL] = id

		out.Packages = append(out.Packages, Package{
			ID:        id,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			PURL:      pkg.PURL,
			Locations: pkg.Locations,
			FoundBy:   pkg.FoundBy,
			Digests:   digestsOf(pkg.Hashes),
		})
	}

	// Which paths identified which package, so evidence edges can be
	// distinguished from plain containment.
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
			out.Files = append(out.Files, File{
				Path:    owned.Path,
				Digests: digestsOf(owned.Hashes),
			})
		}
	}

	// Files that no package claimed.
	for _, f := range resolved.Files {
		out.Files = append(out.Files, File{
			Path:    f.Path,
			Digests: digestsOf(f.Hashes),
		})
	}

	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })

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
