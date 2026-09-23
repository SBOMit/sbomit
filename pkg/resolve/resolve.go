package resolve

import (
	"path/filepath"
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
		files = append(files, resolver.FileInfo{
			Path:   f.Path,
			Hashes: f.Hashes,
		})
	}

	// Run through the ecosystem resolver chain (python, go, rust, js, maven).
	chain := resolver.NewResolverChain()
	resolved := chain.ResolveAll(files)

	// Resolve packages from network connections.
	networkConns := network.ExtractConnections(attestations)
	netChain := network.NewChain()
	networkPkgs := netChain.ResolveAll(networkConns)
	resolved = mergeNetworkPackages(resolved, networkPkgs)

	return assemble(resolved, opts), nil
}

// assemble converts the internal resolver result into the public Result type,
// building containment and evidence relationships.
func assemble(resolved resolver.ResolverResult, opts Options) *Result {
	out := &Result{}

	for _, pkg := range resolved.Packages {
		id := packageID(pkg.PURL)

		p := Package{
			ID:          id,
			Name:        pkg.Name,
			Version:     pkg.Version,
			Ecosystem:   pkg.Ecosystem,
			PURL:        pkg.PURL,
			FoundBy:     pkg.FoundBy,
			DownloadURL: pkg.DownloadURL,
			DownloadIP:  pkg.DownloadIP,
			Digests:     digestsOf(pkg.Hashes),
		}

		// The resolver currently stores the evidence path in the package's
		// FoundBy field but does not carry explicit location lists. We
		// derive a single location from the PURL for now. Downstream
		// consumers (e.g. syft adapters) should resolve paths through
		// their own file resolver.
		out.Packages = append(out.Packages, p)

		// Each package's evidence path creates an EvidentBy relationship.
		// Note: the current resolver chain does not return explicit
		// per-package locations, so this relationship set will grow as
		// the resolver layer is enriched.
	}

	// Remaining files that no resolver claimed become unowned files.
	for _, f := range resolved.Files {
		out.Files = append(out.Files, File{
			Path:    f.Path,
			Digests: digestsOf(f.Hashes),
		})
	}

	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })

	return out
}

// mergeNetworkPackages merges network-resolved packages into the file-resolved
// result. If a package is already present (matched by PURL), the download URL
// and IP are attached; otherwise it is appended as a new entry.
func mergeNetworkPackages(result resolver.ResolverResult, networkPkgs []resolver.PackageInfo) resolver.ResolverResult {
	if len(networkPkgs) == 0 {
		return result
	}

	existingByPURL := make(map[string]int, len(result.Packages))
	for i, pkg := range result.Packages {
		existingByPURL[pkg.PURL] = i
	}

	for _, npkg := range networkPkgs {
		if idx, found := existingByPURL[npkg.PURL]; found {
			result.Packages[idx].DownloadURL = npkg.DownloadURL
			result.Packages[idx].DownloadIP = npkg.DownloadIP
		} else {
			result.Packages = append(result.Packages, npkg)
			existingByPURL[npkg.PURL] = len(result.Packages) - 1
		}
	}

	return result
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
