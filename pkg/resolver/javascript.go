package resolver

import (
	"path"
	"regexp"
	"strings"
)

type JavaScriptResolver struct {
	pnpmPathRe *regexp.Regexp
}

func NewJavaScriptResolver() *JavaScriptResolver {
	return &JavaScriptResolver{
		// pnpm virtual store layout:
		//   node_modules/.pnpm/<name>@<version>(<peers>)/node_modules/<name>/...
		pnpmPathRe: regexp.MustCompile(`node_modules/\.pnpm/([^/]+)/node_modules/(@[^/]+/[^/]+|[^/]+)(?:/|$)`),
	}
}

func (r *JavaScriptResolver) Name() string {
	return "javascript"
}

func (r *JavaScriptResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	byKey := make(map[string]*PackageInfo)
	order := []string{}

	for _, f := range files {
		np := path.Clean(f.Path)

		if !r.isJavaScriptPath(np) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		name, version, ok := r.extractPackage(np)
		if !ok {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		name = NormalizeNpmPackageName(name)
		key := name + "@" + version
		pkg, ok := byKey[key]
		if !ok {
			pkg = &PackageInfo{
				Name:      name,
				Version:   version,
				Ecosystem: "npm",
				PURL:      npmPURL(name, version),
				FoundBy:   "attestation:javascript",
			}
			byKey[key] = pkg
			order = append(order, key)
		}

		if len(pkg.Hashes) == 0 && len(f.Hashes) > 0 {
			pkg.Hashes = f.Hashes
		}
	}

	for _, key := range order {
		packages = append(packages, *byKey[key])
	}

	return packages, remainingFiles
}

func (r *JavaScriptResolver) CreateFileFilters(packages []PackageInfo) []PackageFileFilter {
	var filters []PackageFileFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "npm" {
			continue
		}

		filters = append(filters, &jsPackageFilter{
			packageName: pkg.Name,
			version:     pkg.Version,
		})
	}

	return filters
}

type jsPackageFilter struct {
	packageName string
	version     string
}

func (f *jsPackageFilter) Matches(p string) bool {
	np := path.Clean(p)
	npLower := strings.ToLower(np)

	if !strings.Contains(npLower, "node_modules/") {
		return false
	}

	name := strings.ToLower(f.packageName)
	if name == "" {
		return false
	}

	// Inside a pnpm virtual store, match on the versioned store directory
	// so multiple versions of the same package do not cross-match.
	if strings.Contains(npLower, "/node_modules/.pnpm/") {
		ver := strings.ToLower(f.version)
		if ver == "" {
			return false
		}

		// Scoped separators become '+' in pnpm store directory names.
		pnpmName := strings.ReplaceAll(name, "/", "+")

		return strings.Contains(npLower, "/node_modules/.pnpm/"+pnpmName+"@"+ver)
	}

	return nodeModulesPathContainsPackage(npLower, name)
}

func (r *JavaScriptResolver) isJavaScriptPath(p string) bool {
	return strings.Contains(p, "node_modules") || strings.Contains(p, ".pnpm")
}

// extractPackage resolves the package a path belongs to based on its layout.
//
// Two topologies are supported:
//   - pnpm: node_modules/.pnpm/<name>@<version>(<peers>)/node_modules/<name>/...
//     where the version is encoded in the virtual-store directory name.
//   - npm/yarn classic: node_modules/<name>/... or node_modules/@scope/<name>/...
//     where versions are not part of the path, so packages are reported
//     unversioned and can be enriched later by merging cataloger output.
func (r *JavaScriptResolver) extractPackage(p string) (string, string, bool) {
	if strings.Contains(p, "/node_modules/.pnpm/") {
		return r.extractPnpmPackage(p)
	}
	return r.extractNodeModulesPackage(p)
}

func (r *JavaScriptResolver) extractPnpmPackage(p string) (string, string, bool) {
	matches := r.pnpmPathRe.FindStringSubmatch(p)
	if len(matches) != 3 {
		return "", "", false
	}

	segment := matches[1]
	name := matches[2]
	if isNodeModulesInternalEntry(name) {
		return "", "", false
	}

	version := extractPnpmVersion(segment)
	if version == "" {
		return "", "", false
	}

	return name, version, true
}

func (r *JavaScriptResolver) extractNodeModulesPackage(p string) (string, string, bool) {
	segments := strings.Split(p, "/")

	// Walk from the innermost segment outward so nested layouts such as
	// node_modules/<parent>/node_modules/<child>/... resolve to <child>.
	for i := len(segments) - 2; i >= 0; i-- {
		if segments[i] != "node_modules" {
			continue
		}

		name := segments[i+1]
		if strings.HasPrefix(name, "@") && i+2 < len(segments) {
			name = name + "/" + segments[i+2]
		}

		if name == "" || isNodeModulesInternalEntry(name) {
			continue
		}

		// Standard npm/yarn layouts do not encode versions in paths.
		return name, "", true
	}

	return "", "", false
}

func isNodeModulesInternalEntry(name string) bool {
	return strings.HasPrefix(name, ".")
}

func extractPnpmVersion(segment string) string {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return ""
	}

	if idx := strings.Index(segment, "("); idx != -1 {
		segment = segment[:idx]
	}

	lastAt := strings.LastIndex(segment, "@")
	if lastAt == -1 || lastAt == len(segment)-1 {
		return ""
	}

	return segment[lastAt+1:]
}

// npmPURL builds an npm PURL, omitting the version component when unknown.
func npmPURL(name, version string) string {
	if version == "" {
		return "pkg:npm/" + name
	}
	return "pkg:npm/" + name + "@" + version
}

func nodeModulesPathContainsPackage(p, packageName string) bool {
	return strings.Contains(p, "node_modules/"+packageName+"/")
}

// NormalizeNpmPackageName lowercases and trims an npm package name.
func NormalizeNpmPackageName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	return name
}
