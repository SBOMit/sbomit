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
	seenMeta := make(map[string]struct{}) // Track seen packages by name@version

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
			key := name + "@" + version

			if _, ok := seenMeta[key]; ok {
				continue
			}
			seenMeta[key] = struct{}{}

			purl := "pkg:pypi/" + name + "@" + version
			pkg := PackageInfo{
				Name:      name,
				Version:   version,
				Ecosystem: "pypi",
				PURL:      purl,
				Hashes:    f.Hashes,
				FoundBy:   "attestation:python",
			}
			packages = append(packages, pkg)
			// Don't add this to remainingFiles since it was resolved
		} else {
			// File looks Python-related but couldn't extract package info
			remainingFiles = append(remainingFiles, f)
		}
	}

	return packages, remainingFiles
}

// Filter out files belonging to resolved Python packages
func (r *PythonResolver) CreateFileFilters(packages []PackageInfo) []PackageFileFilter {
	var filters []PackageFileFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "pypi" {
			continue
		}

		filters = append(filters, &pythonPackageFilter{
			packageName: pkg.Name,
			version:     pkg.Version,
		})
	}

	return filters
}

type pythonPackageFilter struct {
	packageName string
	version     string
}

func (f *pythonPackageFilter) Matches(p string) bool {
	np := path.Clean(p)
	npLower := strings.ToLower(np)

	if !strings.Contains(npLower, "site-packages") && !strings.Contains(npLower, "dist-packages") {
		return false
	}

	pkgDirVariants := getPythonPackageDirVariants(f.packageName)

	for _, variant := range pkgDirVariants {
		if strings.Contains(npLower, "/site-packages/"+variant+"/") ||
			strings.Contains(npLower, "/dist-packages/"+variant+"/") {
			return true
		}

		if strings.Contains(npLower, "/site-packages/"+variant+"-") ||
			strings.Contains(npLower, "/dist-packages/"+variant+"-") {
			return true
		}
	}

	return false
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
