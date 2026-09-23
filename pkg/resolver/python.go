package resolver

import (
	"path"
	"regexp"
	"strings"
)

type PythonResolver struct {
	metadataPattern *regexp.Regexp
}

func NewPythonResolver() *PythonResolver {
	return &PythonResolver{
		// Matches: "site-packages/foo-1.2.3.dist-info" or "dist-packages/foo-1.2.3.egg-info"
		// Group 1: optional prefix (site-packages/ or dist-packages/)
		// Group 2: package name
		// Group 3: version
		// Group 4: info type (dist-info or egg-info)
		metadataPattern: regexp.MustCompile(`(?:dist-packages|site-packages)/([^/]+)-([0-9A-Za-z\.\+\-_]+)\.(dist-info|egg-info)`),
	}
}

func (r *PythonResolver) Name() string {
	return "python"
}

func (r *PythonResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	g := newGroup()

	for _, f := range files {
		np := path.Clean(f.Path)

		if !r.isPythonPath(np) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		matches := r.metadataPattern.FindStringSubmatch(np)
		if len(matches) >= 4 {
			name := NormalizePackageName(matches[1])
			version := matches[2]

			g.add(name+"@"+version, PackageInfo{
				Name:      name,
				Version:   version,
				Ecosystem: "pypi",
				PURL:      "pkg:pypi/" + name + "@" + version,
				FoundBy:   "attestation:python",
			}, f)
		} else {
			// File looks Python-related but couldn't extract package info
			remainingFiles = append(remainingFiles, f)
		}
	}

	packages, rest := g.finish(rankPythonEvidence)
	return packages, append(remainingFiles, rest...)
}

// rankPythonEvidence prefers the file that actually declares the distribution.
// RECORD, WHEEL and INSTALLER sit in the same dist-info directory but are
// installer boilerplate, identical across packages, so they rank below an
// ordinary module source file.
func rankPythonEvidence(p string) int {
	switch strings.ToUpper(path.Base(p)) {
	case "METADATA", "PKG-INFO":
		return 2
	case "RECORD", "WHEEL", "INSTALLER":
		return 0
	default:
		return 1
	}
}

// OwnershipFilters attributes files under a package's directory to it.
func (r *PythonResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "pypi" {
			continue
		}

		// Precomputed, so matching doesn't concatenate on every comparison.
		variants := getPythonPackageDirVariants(pkg.Name)
		needles := make([]string, 0, len(variants)*4)
		for _, v := range variants {
			needles = append(needles,
				"/site-packages/"+v+"/",
				"/dist-packages/"+v+"/",
				"/site-packages/"+v+"-",
				"/dist-packages/"+v+"-",
			)
		}

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				if !strings.Contains(p.Lower, "site-packages") && !strings.Contains(p.Lower, "dist-packages") {
					return false
				}
				for _, n := range needles {
					if strings.Contains(p.Lower, n) {
						return true
					}
				}
				return false
			}),
		})
	}

	return filters
}

func getPythonPackageDirVariants(name string) []string {
	variants := make(map[string]struct{})

	// Lowercase (for case-insensitive matching)
	lower := strings.ToLower(name)
	variants[lower] = struct{}{}

	// Replace hyphens with underscores (common in Python)
	withUnderscores := strings.ReplaceAll(lower, "-", "_")
	variants[withUnderscores] = struct{}{}

	// Replace underscores with hyphens
	withHyphens := strings.ReplaceAll(lower, "_", "-")
	variants[withHyphens] = struct{}{}

	// Add private module prefix variant (_pytest for pytest)
	variants["_"+lower] = struct{}{}
	variants["_"+withUnderscores] = struct{}{}

	result := make([]string, 0, len(variants))
	for v := range variants {
		result = append(result, v)
	}
	return result
}

func (r *PythonResolver) isPythonPath(p string) bool {
	return strings.Contains(p, "site-packages") ||
		strings.Contains(p, "dist-packages") ||
		strings.Contains(p, ".egg-info") ||
		strings.Contains(p, ".dist-info")
}

// NormalizePackageName normalizes a Python package name according to PEP 503.
func NormalizePackageName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	// Remove multiple consecutive hyphens
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return name
}
