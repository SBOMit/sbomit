package resolver

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

type RustResolver struct {
	// Requires a trailing "/" so filenames (UTF-8-demo.txt) don't match.
	crateDirWithVerRe *regexp.Regexp
	crateFileWithVer  *regexp.Regexp
	// registry/src/<index>/<name>-<version>/
	registrySrcRe *regexp.Regexp
}

func NewRustResolver() *RustResolver {
	return &RustResolver{
		crateDirWithVerRe: regexp.MustCompile(`([^/]+)-([0-9][0-9A-Za-z\.\-\+]*)/`),
		crateFileWithVer:  regexp.MustCompile(`([^/]+)-([0-9][0-9A-Za-z\.\-\+]*)\.crate$`),
		registrySrcRe:     regexp.MustCompile(`/registry/src/[^/]+/([^/]+)-([0-9][0-9A-Za-z\.\-\+]*)/`),
	}
}

func (r *RustResolver) Name() string {
	return "rust"
}

// crate is one version of one crate; a registry often holds several versions.
type crate struct {
	name    string
	version string
}

func (c crate) key() string { return c.name + "@" + c.version }

func (r *RustResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	candidates := map[crate][]FileInfo{}

	for _, f := range files {
		pp := path.Clean(strings.TrimSpace(f.Path))

		if !r.isRustPath(pp) {
			continue
		}

		if r.isRustIgnoredPath(pp) {
			continue
		}

		if c, ok := r.identify(pp); ok {
			candidates[c] = append(candidates[c], f)
		}
	}

	// Pass every path on: crate files are assigned to their crate later, and
	// FileFilter alone decides what is noise.
	remainingFiles = append(remainingFiles, files...)

	// Sorted for stable output.
	keys := make([]crate, 0, len(candidates))
	for c := range candidates {
		if c.name == "" || c.version == "" {
			continue
		}
		keys = append(keys, c)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].key() < keys[j].key() })

	for _, c := range keys {
		// Other files are already in remainingFiles.
		evidence, _ := pickEvidence(candidates[c], rankRustEvidence)

		pkg := PackageInfo{
			Name:      c.name,
			Version:   c.version,
			Ecosystem: "cargo",
			PURL:      "pkg:cargo/" + c.name + "@" + c.version,
			PkgMgr:    "cargo",
			Locations: []string{evidence.Path},
			Artifact:  artifactFile(candidates[c], isCrateArtifact),
		}

		packages = append(packages, pkg)
	}

	return packages, remainingFiles
}

// isCrateArtifact reports whether a path is a .crate in the registry cache.
func isCrateArtifact(p string) bool {
	return strings.HasSuffix(strings.ToLower(p), ".crate") &&
		strings.Contains(p, "/registry/cache/")
}

// rankRustEvidence prefers the .crate, then Cargo.toml.
func rankRustEvidence(p string) int {
	base := strings.ToLower(path.Base(p))
	switch {
	case isCrateArtifact(p):
		return 3
	case base == "cargo.toml":
		return 2
	case base == ".cargo-checksum.json":
		return 0
	default:
		return 1
	}
}

func (r *RustResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "cargo" {
			continue
		}

		name := strings.ToLower(NormalizeRustCrateName(pkg.Name))
		ver := pkg.Version
		if name == "" || ver == "" {
			continue
		}

		// Precomputed, so matching doesn't concatenate on every comparison.
		crateNeedle := "/" + name + "-" + ver + ".crate"
		dirNeedle := "/" + name + "-" + ver + "/"

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				inRegistry := strings.Contains(p.Lower, "/registry/")
				inCrates := strings.Contains(p.Lower, "/crates/")
				if !inRegistry && !inCrates {
					return false
				}

				if strings.Contains(p.Lower, "/registry/cache/") && strings.Contains(p.Lower, crateNeedle) {
					return true
				}
				if strings.Contains(p.Lower, "/registry/src/") && strings.Contains(p.Lower, dirNeedle) {
					return true
				}
				return inCrates && strings.Contains(p.Lower, dirNeedle)
			}),
		})
	}

	return filters
}

func (r *RustResolver) isRustPath(p string) bool {
	return strings.Contains(p, "/registry/") ||
		strings.Contains(p, "/crates/") ||
		strings.Contains(p, ".crate") ||
		strings.Contains(p, ".fingerprint") ||
		strings.Contains(p, "/target/") ||
		strings.Contains(p, "Cargo.lock")
}

// isRustIgnoredPath reports build output, which identifies no crate.
func (r *RustResolver) isRustIgnoredPath(p string) bool {
	return strings.Contains(p, "/.fingerprint/") || strings.Contains(p, "/target/")
}

// identify returns the crate a registry path belongs to, trying the most
// specific path pattern first. The index directory (index.crates.io-<hash>) looks
// like a crate directory, so patterns are anchored on the registry subtree.
func (r *RustResolver) identify(p string) (crate, bool) {
	if strings.Contains(p, "/registry/cache/") {
		if m := r.crateFileWithVer.FindStringSubmatch(p); len(m) == 3 {
			return crate{NormalizeRustCrateName(m[1]), m[2]}, true
		}
		return crate{}, false
	}

	if m := r.registrySrcRe.FindStringSubmatch(p); len(m) == 3 {
		return crate{NormalizeRustCrateName(m[1]), m[2]}, true
	}

	// Vendored crates: fall back to the last versioned directory.
	if strings.Contains(p, "/crates/") {
		if all := r.crateDirWithVerRe.FindAllStringSubmatch(p, -1); len(all) > 0 {
			last := all[len(all)-1]
			if len(last) == 3 {
				return crate{NormalizeRustCrateName(last[1]), last[2]}, true
			}
		}
	}

	return crate{}, false
}

// NormalizeRustCrateName lowercases and trims a Cargo crate name.
func NormalizeRustCrateName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
