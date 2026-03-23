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
		pnpmPathRe: regexp.MustCompile(`node_modules/\.pnpm/([^/]+)/node_modules/(@[^/]+/[^/]+|[^/]+)(?:/|$)`),
	}
}

func (r *JavaScriptResolver) Name() string {
	return "javascript"
}

func (r *JavaScriptResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	seen := make(map[string]struct{})

	for _, f := range files {
		np := path.Clean(f.Path)

		if !r.isJavaScriptPath(np) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		name, version, ok := r.extractPnpmPackage(np)
		if !ok {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		name = NormalizeNpmPackageName(name)
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		purl := "pkg:npm/" + name + "@" + version
		pkg := PackageInfo{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
			PURL:      purl,
			Hashes:    f.Hashes,
			FoundBy:   "attestation:javascript",
		}
		packages = append(packages, pkg)
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

	if !strings.Contains(npLower, "/node_modules/.pnpm/") {
		return false
	}

	name := strings.ToLower(f.packageName)
	ver := strings.ToLower(f.version)
	if name == "" || ver == "" {
		return false
	}

	pnpmName := strings.ReplaceAll(name, "/", "+")
	if strings.HasPrefix(pnpmName, "@") {
		pnpmName = "@" + strings.TrimPrefix(pnpmName, "@")
	}

	if strings.Contains(npLower, "/node_modules/.pnpm/"+pnpmName+"@"+ver) &&
		strings.Contains(npLower, "/node_modules/"+name+"/") {
		return true
	}

	return false
}

func (r *JavaScriptResolver) isJavaScriptPath(p string) bool {
	return strings.Contains(p, "node_modules") || strings.Contains(p, ".pnpm")
}

func (r *JavaScriptResolver) extractPnpmPackage(p string) (string, string, bool) {
	matches := r.pnpmPathRe.FindStringSubmatch(p)
	if len(matches) != 3 {
		return "", "", false
	}

	segment := matches[1]
	name := matches[2]
	version := extractPnpmVersion(segment)
	if version == "" {
		return "", "", false
	}

	return name, version, true
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

// NormalizeNpmPackageName lowercases and trims an npm package name.
func NormalizeNpmPackageName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	return name
}
