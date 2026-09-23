package resolver

import (
	"path"
	"sort"
	"strings"
)

type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // pypi, golang, cargo, npm, etc.
	PURL      string `json:"purl"`
	// Hashes should be the digest of the package artifact itself: the wheel,
	// tarball, crate, or module that was distributed as the package.
	// It must never hold the digest of an individual file that merely belongs
	// to the package. A package checksum that is really a member-file checksum
	// cannot be verified against anything the registry publishes.
	//
	// Path resolution cannot establish this, so it is always empty today. It
	// becomes populatable once download evidence is available again.
	Hashes  map[string]string `json:"hashes,omitempty"`
	FoundBy string            `json:"found_by"` // which resolver found this

	// Locations are the attested paths that evidenced this package, not the
	// full set of files it owns. Ownership is in ResolverResult.Owned.
	Locations []string `json:"locations,omitempty"`
}

type FileInfo struct {
	Path string `json:"path"`
	// File digests stay on file nodes.
	Hashes map[string]string `json:"hashes,omitempty"`
}

// OwnedFile is a file attributed to a package.
type OwnedFile struct {
	FileInfo
	OwnerPURL string `json:"owner_purl"`
}

type ResolverResult struct {
	Packages []PackageInfo `json:"packages"`

	// Owned are files attributed to a package, named by OwnerPURL. A file can
	// sit inside a package's directory without being the file that identified
	// it, so this is a superset of every package's Locations.
	Owned []OwnedFile `json:"owned,omitempty"`

	// Files are the paths no package claimed — config read during the build,
	// system libraries linked against, scripts executed.
	Files []FileInfo `json:"files"`
}

// Path is a file path with the normalized forms matchers need.
//
// Attribution tests every unclaimed file against every package's filter, so it
// is O(files x packages) — millions of comparisons on a large build.
// Normalizing once per file rather than once per comparison keeps it cheap.
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
			NewMavenResolver(),
		},
		filter: NewFileFilter(),
	}
}

func (c *ResolverChain) AddResolver(r Resolver) {
	c.resolvers = append(c.resolvers, r)
}

// ResolveAll processes all files through the resolver chain:
//  1. Filter out unwanted files (cache, temp, system files).
//  2. Pass files through each resolver in sequence. Each claims the packages it
//     recognizes, records the path that evidenced each one in Locations, and
//     passes everything it did not claim to the next.
//  3. Attribute the leftovers: every unclaimed file is tested against each
//     recognized package's ownership filters, since a file can sit inside a
//     package's directory without being the file that identified it.
//  4. Whatever no package claims ends up in Files.
func (c *ResolverChain) ResolveAll(files []FileInfo) ResolverResult {
	result := ResolverResult{
		Packages: []PackageInfo{},
		Files:    []FileInfo{},
	}

	// Step 1: Filter files first
	var filteredFiles []FileInfo
	for _, f := range files {
		if c.filter.ShouldInclude(f.Path) {
			filteredFiles = append(filteredFiles, f)
		}
	}

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

// attribute assigns files to the packages that own them. Evidence paths are
// added first so their digests survive: a file reached through a resolver's
// ownership filter may carry a barer record than the one originally observed.
func attribute(observed, unclaimed []FileInfo, packages []PackageInfo, filters []OwnershipFilter) (owned []OwnedFile, unowned []FileInfo) {
	digestsByPath := make(map[string]map[string]string, len(observed))
	for _, f := range observed {
		digestsByPath[f.Path] = f.Hashes
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
			addOwned(FileInfo{Path: loc, Hashes: digestsByPath[loc]}, pkg.PURL)
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

// pickEvidence chooses which of a package's paths to cite as its evidence, and
// returns the rest for ownership attribution.
//
// Without ranking, the evidence would be whichever file was seen first, which
// is arbitrary: a Maven artifact would cite _remote.repositories over its jar.
// Ties break on the smaller path so the result is stable across runs.
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

// finish resolves each group into a package plus its non-evidence files. The
// non-evidence files are returned so the caller can hand them back for
// ownership attribution rather than dropping them.
func (g *group) finish(rank func(string) int) ([]PackageInfo, []FileInfo) {
	packages := make([]PackageInfo, 0, len(g.order))
	var rest []FileInfo

	for _, key := range g.order {
		evidence, others := pickEvidence(g.files[key], rank)

		pkg := g.meta[key]
		pkg.Locations = []string{evidence.Path}
		packages = append(packages, pkg)

		rest = append(rest, others...)
	}

	return packages, rest
}
