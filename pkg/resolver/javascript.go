package resolver

import (
	"path"
	"regexp"
	"strings"
)

type JavaScriptResolver struct {
	pnpmPathRe       *regexp.Regexp
	npmPackageJsonRe *regexp.Regexp
	yarnCacheRe      *regexp.Regexp
}

func NewJavaScriptResolver() *JavaScriptResolver {
	return &JavaScriptResolver{
		
		pnpmPathRe: regexp.MustCompile(`node_modules/\.pnpm/([^/]+)/node_modules/(@[^/]+/[^/]+|[^/]+)(?:/|$)`),

		npmPackageJsonRe: regexp.MustCompile(`node_modules/(@[^/]+/[^/]+|[^/]+)/package\.json$`),

		
		yarnCacheRe: regexp.MustCompile(`\.yarn/cache/(.+)-npm-([0-9][^-]*)-[a-f0-9]+-[a-f0-9]+\.zip$`),
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

		
		name, version, foundBy, ok := r.extractPackage(np)
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
			FoundBy:   foundBy,
		}
		packages = append(packages, pkg)
	}

	return packages, remainingFiles
}


func (r *JavaScriptResolver) extractPackage(p string) (string, string, string, bool) {
	
	if name, version, ok := r.extractPnpmPackage(p); ok {
		return name, version, "attestation:javascript:pnpm", true
	}

	
	if name, version, ok := r.extractYarnBerryPackage(p); ok {
		return name, version, "attestation:javascript:yarn-berry", true
	}

	
	if name, ok := r.extractNpmPackage(p); ok {
		return name, "unknown", "attestation:javascript:npm", true
	}

	return "", "", "", false
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
	name := strings.ToLower(f.packageName)

	if name == "" {
		return false
	}

	
	if strings.Contains(npLower, "/node_modules/.pnpm/") {
		ver := strings.ToLower(f.version)
		if ver == "" {
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
	}

	
	if strings.Contains(npLower, "/node_modules/"+name+"/") &&
		!strings.Contains(npLower, "/node_modules/.pnpm/") {
		return true
	}

	
	if strings.Contains(npLower, "/.yarn/cache/") {
		yarnName := yarnCacheName(name)
		ver := strings.ToLower(f.version)
		if ver != "" && ver != "unknown" {
			if strings.Contains(npLower, "/"+yarnName+"-npm-"+ver+"-") {
				return true
			}
		}
	}

	return false
}


func yarnCacheName(name string) string {
	return strings.ReplaceAll(name, "/", "-")
}

func (r *JavaScriptResolver) isJavaScriptPath(p string) bool {
	return strings.Contains(p, "node_modules") ||
		strings.Contains(p, ".pnpm") ||
		strings.Contains(p, ".yarn/cache")
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


func (r *JavaScriptResolver) extractNpmPackage(p string) (string, bool) {
	
	if strings.Contains(p, "node_modules/.pnpm") {
		return "", false
	}

	matches := r.npmPackageJsonRe.FindStringSubmatch(p)
	if len(matches) != 2 {
		return "", false
	}

	name := matches[1]

	
	if strings.HasPrefix(name, ".") {
		return "", false
	}

	return name, true
}


func (r *JavaScriptResolver) extractYarnBerryPackage(p string) (string, string, bool) {
	matches := r.yarnCacheRe.FindStringSubmatch(p)
	if len(matches) != 3 {
		return "", "", false
	}

	rawName := matches[1]
	version := matches[2]

	name := decodeYarnCacheName(rawName)

	return name, version, true
}


func decodeYarnCacheName(raw string) string {
	if !strings.HasPrefix(raw, "@") {
		return raw
	}

	
	withoutAt := raw[1:]
	idx := strings.Index(withoutAt, "-")
	if idx == -1 {
		return raw
	}

	scope := withoutAt[:idx]
	name := withoutAt[idx+1:]
	return "@" + scope + "/" + name
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
