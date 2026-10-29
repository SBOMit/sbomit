package resolver

import (
	"path"
	"sort"
	"strings"

	"github.com/sbomit/sbomit/pkg/attestation"
)

// Digest is a hash algorithm and its hex-encoded value.
type Digest = attestation.Digest

type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // the PURL type: pypi, conda, golang, cargo, npm, maven
	PURL      string `json:"purl"`

	// PkgMgr is the package manager whose paths identified the package.
	PkgMgr string `json:"pkgmgr"`

	// Locations are the attested paths that evidenced this package, not the
	// full set of files it owns. Ownership is in ResolverResult.Owned.
	Locations []string `json:"locations,omitempty"`

	// Artifact is the package's artifact file (wheel, .crate, .conda, module
	// .zip, jar) if the build touched it. It may also be in Locations.
	Artifact *FileInfo `json:"artifact,omitempty"`
}

type FileInfo struct {
	Path string `json:"path"`
	// Digests recorded for the path; may be empty or hold several values.
	Digests []Digest `json:"digests,omitempty"`
}

// OwnedFile is a file attributed to a package.
type OwnedFile struct {
	FileInfo
	OwnerPURL string `json:"owner_purl"`
}

type ResolverResult struct {
	Packages []PackageInfo `json:"packages"`

	// Owned are files attributed to a package, a superset of Locations.
	Owned []OwnedFile `json:"owned,omitempty"`

	// Files are the paths no package claimed.
	Files []FileInfo `json:"files"`
}

// Path is a file path with the normalized forms matchers need, computed once
// since attribution compares every file against every package.
type Path struct {
	Raw   string
	Clean string
	Lower string
}

// NewPath normalizes a path once for repeated matching.
func NewPath(raw string) Path {
	clean := path.Clean(raw)
	return Path{Raw: raw, Clean: clean, Lower: strings.ToLower(clean)}
}

// Matcher reports whether a path belongs to a particular package.
type Matcher interface {
	Matches(Path) bool
}

// MatcherFunc adapts a function to Matcher.
type MatcherFunc func(Path) bool

func (f MatcherFunc) Matches(p Path) bool { return f(p) }

// OwnershipFilter attributes matching paths to the package identified by PURL.
type OwnershipFilter struct {
	PURL    string
	Matcher Matcher
}

type Resolver interface {
	// Name returns the name of this resolver (e.g., "python", "go", "rust")
	Name() string

	// Resolve takes a list of file paths with hashes and returns:
	// - packages: successfully resolved packages
	// - remainingFiles: files that this resolver couldn't resolve (passed to next resolver)
	Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo)
}

type ResolverChain struct {
	resolvers []Resolver
	filter    *FileFilter
}

// NewResolverChain creates a new resolver chain with default resolvers
func NewResolverChain() *ResolverChain {
	return &ResolverChain{
		resolvers: []Resolver{
			NewPythonResolver(),
			NewGoResolver(),
			NewRustResolver(),
			NewJavaScriptResolver(),
			NewJavaResolver(),
		},
		filter: NewFileFilter(),
	}
}

func (c *ResolverChain) AddResolver(r Resolver) {
	c.resolvers = append(c.resolvers, r)
}

// ResolveAll filters out noise, runs each resolver in turn on what the previous
// ones did not claim, attributes the leftovers to packages by their ownership
// filters, and returns the rest as Files.
func (c *ResolverChain) ResolveAll(files []FileInfo) ResolverResult {
	result := ResolverResult{
		Packages: []PackageInfo{},
		Files:    []FileInfo{},
	}

	// Step 1: Filter files first
	filteredFiles := c.filter.Filter(files)

	// Step 2: Pass through resolver chain
	remainingFiles := filteredFiles
	seenPackages := make(map[string]bool)
	var filters []OwnershipFilter

	for _, resolver := range c.resolvers {
		packages, notResolved := resolver.Resolve(remainingFiles)

		var kept []PackageInfo
		for _, pkg := range packages {
			if !seenPackages[pkg.PURL] {
				seenPackages[pkg.PURL] = true
				result.Packages = append(result.Packages, pkg)
				kept = append(kept, pkg)
			}
		}

		if of, ok := resolver.(OwnershipFilterer); ok && len(kept) > 0 {
			filters = append(filters, of.OwnershipFilters(kept)...)
		}

		// Pass remaining files to next resolver
		remainingFiles = notResolved
	}

	// Step 3: Attribute every unclaimed file to the package that owns it.
	result.Owned, result.Files = attribute(filteredFiles, remainingFiles, result.Packages, filters)

	return result
}

// attribute assigns files to the packages that own them, cited paths first.
func attribute(observed, unclaimed []FileInfo, packages []PackageInfo, filters []OwnershipFilter) (owned []OwnedFile, unowned []FileInfo) {
	digestsByPath := make(map[string][]Digest, len(observed))
	for _, f := range observed {
		digestsByPath[f.Path] = f.Digests
	}

	seen := make(map[string]struct{})
	addOwned := func(f FileInfo, purl string) {
		key := purl + "\x00" + f.Path
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		owned = append(owned, OwnedFile{FileInfo: f, OwnerPURL: purl})
	}

	for _, pkg := range packages {
		for _, loc := range pkg.Locations {
			addOwned(FileInfo{Path: loc, Digests: digestsByPath[loc]}, pkg.PURL)
		}
	}

	for _, f := range unclaimed {
		if purl, ok := ownerOf(NewPath(f.Path), filters); ok {
			addOwned(f, purl)
			continue
		}
		unowned = append(unowned, f)
	}

	sort.Slice(owned, func(i, j int) bool {
		if owned[i].OwnerPURL != owned[j].OwnerPURL {
			return owned[i].OwnerPURL < owned[j].OwnerPURL
		}
		return owned[i].Path < owned[j].Path
	})
	sort.Slice(unowned, func(i, j int) bool { return unowned[i].Path < unowned[j].Path })

	return owned, unowned
}

// ownerOf returns the PURL of the first package whose filter claims the path.
func ownerOf(p Path, filters []OwnershipFilter) (string, bool) {
	for _, f := range filters {
		if f.Matcher.Matches(p) {
			return f.PURL, true
		}
	}
	return "", false
}

// OwnershipFilterer is implemented by resolvers that can attribute a package's
// member files to it.
type OwnershipFilterer interface {
	// OwnershipFilters returns, per package, a predicate matching the paths it owns.
	OwnershipFilters(packages []PackageInfo) []OwnershipFilter
}

// pickEvidence returns the highest-ranked path to cite and the rest. Ties break
// on the smaller path for stable output.
func pickEvidence(files []FileInfo, rank func(string) int) (evidence FileInfo, rest []FileInfo) {
	if len(files) == 0 {
		return FileInfo{}, nil
	}

	best := 0
	bestRank := rank(files[0].Path)
	for i := 1; i < len(files); i++ {
		r := rank(files[i].Path)
		if r > bestRank || (r == bestRank && files[i].Path < files[best].Path) {
			best, bestRank = i, r
		}
	}

	rest = make([]FileInfo, 0, len(files)-1)
	for i, f := range files {
		if i == best {
			continue
		}
		rest = append(rest, f)
	}

	return files[best], rest
}

// group accumulates files by package key, preserving first-seen order.
type group struct {
	order []string
	files map[string][]FileInfo
	meta  map[string]PackageInfo
}

func newGroup() *group {
	return &group{
		files: map[string][]FileInfo{},
		meta:  map[string]PackageInfo{},
	}
}

// add records a file against a package key.
func (g *group) add(key string, pkg PackageInfo, f FileInfo) {
	if _, ok := g.files[key]; !ok {
		g.order = append(g.order, key)
		g.meta[key] = pkg
	}
	g.files[key] = append(g.files[key], f)
}

// finish turns each group into a package and returns its non-cited files for
// attribution. Any file matching isArtifact becomes PackageInfo.Artifact,
// even if another file is cited. isArtifact is nil if the package manager
// leaves no artifact on disk.
func (g *group) finish(rank func(string) int, isArtifact func(string) bool) ([]PackageInfo, []FileInfo) {
	packages := make([]PackageInfo, 0, len(g.order))
	var rest []FileInfo

	for _, key := range g.order {
		evidence, others := pickEvidence(g.files[key], rank)

		pkg := g.meta[key]
		pkg.Locations = []string{evidence.Path}
		if isArtifact != nil {
			pkg.Artifact = artifactFile(g.files[key], isArtifact)
		}
		packages = append(packages, pkg)

		rest = append(rest, others...)
	}

	return packages, rest
}

// artifactFile returns the group's artifact, preferring one with a digest, then
// the smaller path. Nil if there is none.
func artifactFile(files []FileInfo, isArtifact func(string) bool) *FileInfo {
	var best *FileInfo

	for i := range files {
		f := files[i]
		if !isArtifact(f.Path) {
			continue
		}
		switch {
		case best == nil,
			len(f.Digests) > 0 && len(best.Digests) == 0,
			(len(f.Digests) > 0) == (len(best.Digests) > 0) && f.Path < best.Path:
			c := f
			best = &c
		}
	}

	return best
}
