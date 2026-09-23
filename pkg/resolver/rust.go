package resolver

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

type RustResolver struct {
	crateDirWithVerRe *regexp.Regexp
	crateFileWithVer  *regexp.Regexp
}

func NewRustResolver() *RustResolver {
	return &RustResolver{
		crateDirWithVerRe: regexp.MustCompile(`([^/]+)-([0-9][0-9A-Za-z\.\-\+]*)(?:/|$)`),
		crateFileWithVer:  regexp.MustCompile(`([^/]+)-([0-9][0-9A-Za-z\.\-\+]*)\.crate$`),
	}
}

func (r *RustResolver) Name() string {
	return "rust"
}

func (r *RustResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	chosenByName := map[string]string{}
	candidates := map[string][]FileInfo{}

	for _, f := range files {
		pp := path.Clean(strings.TrimSpace(f.Path))

		if !r.isRustPath(pp) {
			continue
		}

		if r.isRustIgnoredPath(pp) {
			continue
		}

		if m := r.crateFileWithVer.FindStringSubmatch(pp); len(m) == 3 {
			if r.isCargoRegistryPath(pp) {
				name := NormalizeRustCrateName(m[1])
				chosenByName[name] = m[2]
				candidates[name] = append(candidates[name], f)
			}
			continue
		}

		if name, version, ok := r.findLastCrateDirWithVer(pp); ok {
			if r.isCargoRegistryPath(pp) || strings.Contains(pp, "/crates/") || strings.Contains(pp, "/registry/src/") {
				name = NormalizeRustCrateName(name)
				chosenByName[name] = version
				candidates[name] = append(candidates[name], f)
			}
			continue
		}
	}

	for _, f := range files {
		pp := path.Clean(strings.TrimSpace(f.Path))

		if !r.isRustPath(pp) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		if r.isRustIgnoredPath(pp) {
			continue
		}

		if r.isCompiledRustArtifact(pp) {
			if r.isOwnedByKnownCrate(pp, chosenByName) {
				continue
			}
		}

		remainingFiles = append(remainingFiles, f)
	}

	// Sorted, because map iteration order is random and package order would
	// otherwise differ between runs on identical input.
	names := make([]string, 0, len(chosenByName))
	for name := range chosenByName {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		version := chosenByName[name]
		if name == "" || version == "" {
			continue
		}

		// Non-evidence files are already carried by the second pass above, so
		// only the citation is taken here.
		evidence, _ := pickEvidence(candidates[name], rankRustEvidence)

		packages = append(packages, PackageInfo{
			Name:      name,
			Version:   version,
			Ecosystem: "cargo",
			PURL:      "pkg:cargo/" + strings.ToLower(name) + "@" + version,
			FoundBy:   "attestation:rust",
			Locations: []string{evidence.Path},
		})
	}

	return packages, remainingFiles
}

// rankRustEvidence prefers the .crate archive: it is the artifact crates.io
// publishes. Cargo.toml declares the crate, so it comes next.
func rankRustEvidence(p string) int {
	base := strings.ToLower(path.Base(p))
	switch {
	case strings.HasSuffix(base, ".crate"):
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

func (r *RustResolver) isCargoRegistryPath(p string) bool {
	return strings.Contains(p, "/registry/cache/") ||
		strings.Contains(p, "/registry/src/") ||
		strings.Contains(p, "index.crates.io") ||
		strings.Contains(p, ".crate")
}

func (r *RustResolver) isRustIgnoredPath(p string) bool {
	return strings.Contains(p, "/.fingerprint/") || strings.Contains(p, "/target/")
}

func (r *RustResolver) isCompiledRustArtifact(p string) bool {
	return strings.HasSuffix(p, ".d") ||
		strings.HasSuffix(p, ".rlib") ||
		strings.HasSuffix(p, ".rmeta") ||
		strings.HasSuffix(p, ".so")
}

func (r *RustResolver) isOwnedByKnownCrate(p string, chosenByName map[string]string) bool {
	for name := range chosenByName {
		if strings.HasPrefix(p, name+"/") || strings.Contains(p, "/"+name+"/") || strings.Contains(p, "/"+name+"-") {
			return true
		}
	}
	return false
}

func (r *RustResolver) findLastCrateDirWithVer(p string) (string, string, bool) {
	allMatches := r.crateDirWithVerRe.FindAllStringSubmatch(p, -1)
	if len(allMatches) == 0 {
		return "", "", false
	}
	last := allMatches[len(allMatches)-1]
	if len(last) != 3 {
		return "", "", false
	}
	return last[1], last[2], true
}

// NormalizeRustCrateName lowercases and trims a Cargo crate name.
func NormalizeRustCrateName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
