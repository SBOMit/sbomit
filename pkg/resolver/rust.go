package resolver

import (
	"path"
	"regexp"
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
				chosenByName[NormalizeRustCrateName(m[1])] = m[2]
			}
			continue
		}

		if name, version, ok := r.findLastCrateDirWithVer(pp); ok {
			if r.isCargoRegistryPath(pp) || strings.Contains(pp, "/crates/") || strings.Contains(pp, "/registry/src/") {
				chosenByName[NormalizeRustCrateName(name)] = version
				continue
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

	for name, version := range chosenByName {
		if name == "" || version == "" {
			continue
		}
		purlName := strings.ToLower(name)
		purl := "pkg:cargo/" + purlName + "@" + version
		pkg := PackageInfo{
			Name:      name,
			Version:   version,
			Ecosystem: "cargo",
			PURL:      purl,
			FoundBy:   "attestation:rust",
		}
		packages = append(packages, pkg)
	}

	return packages, remainingFiles
}

func (r *RustResolver) CreateFileFilters(packages []PackageInfo) []PackageFileFilter {
	var filters []PackageFileFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "cargo" {
			continue
		}

		filters = append(filters, &rustPackageFilter{
			packageName: NormalizeRustCrateName(pkg.Name),
			version:     pkg.Version,
		})
	}

	return filters
}

type rustPackageFilter struct {
	packageName string
	version     string
}

func (f *rustPackageFilter) Matches(p string) bool {
	np := path.Clean(p)
	npLower := strings.ToLower(np)

	if !strings.Contains(npLower, "/registry/") && !strings.Contains(npLower, "/crates/") {
		return false
	}

	name := strings.ToLower(f.packageName)
	ver := f.version
	if name == "" || ver == "" {
		return false
	}

	if strings.Contains(npLower, "/registry/cache/") && strings.Contains(npLower, "/"+name+"-"+ver+".crate") {
		return true
	}

	if strings.Contains(npLower, "/registry/src/") && strings.Contains(npLower, "/"+name+"-"+ver+"/") {
		return true
	}

	if strings.Contains(npLower, "/crates/") && strings.Contains(npLower, "/"+name+"-"+ver+"/") {
		return true
	}

	return false
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
