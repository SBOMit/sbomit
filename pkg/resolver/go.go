package resolver

import (
	"path"
	"regexp"
	"strings"
)

type GoResolver struct {
	moduleDirRe   *regexp.Regexp
	moduleCacheRe *regexp.Regexp
}

func NewGoResolver() *GoResolver {
	return &GoResolver{
		moduleDirRe:   regexp.MustCompile(`pkg/mod/([^@]+)@([^/]+)/`),
		moduleCacheRe: regexp.MustCompile(`pkg/mod/cache/download/(.+)/@v/([^/]+)\.(mod|zip|info)`),
	}
}

func (r *GoResolver) Name() string {
	return "go"
}

func (r *GoResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	seen := make(map[string]struct{})

	for _, f := range files {
		np := path.Clean(f.Path)

		if !r.isGoPath(np) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		module, version, ok := r.extractModuleVersion(np)
		if !ok {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		module = DecodeGoModulePath(module)
		key := module + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		purl := "pkg:golang/" + module + "@" + version
		pkg := PackageInfo{
			Name:      module,
			Version:   version,
			Ecosystem: "golang",
			PURL:      purl,
			Hashes:    f.Hashes,
			FoundBy:   "attestation:go",
		}
		packages = append(packages, pkg)
	}

	return packages, remainingFiles
}

func (r *GoResolver) CreateFileFilters(packages []PackageInfo) []PackageFileFilter {
	var filters []PackageFileFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "golang" {
			continue
		}

		filters = append(filters, &goPackageFilter{
			modulePath: pkg.Name,
			version:    pkg.Version,
		})
	}

	return filters
}

type goPackageFilter struct {
	modulePath string
	version    string
}

func (f *goPackageFilter) Matches(p string) bool {
	np := path.Clean(p)
	npLower := strings.ToLower(np)
	version := strings.ToLower(f.version)

	if !strings.Contains(npLower, "/pkg/mod/") {
		return false
	}

	variants := goModulePathVariants(f.modulePath)
	for _, variant := range variants {
		variantLower := strings.ToLower(variant)
		if strings.Contains(npLower, "/pkg/mod/"+variantLower+"@"+version+"/") {
			return true
		}
		if strings.Contains(npLower, "/pkg/mod/cache/download/"+variantLower+"/@v/"+version+".") {
			return true
		}
	}

	return false
}

func (r *GoResolver) isGoPath(p string) bool {
	return strings.Contains(p, "/pkg/mod/")
}

func (r *GoResolver) extractModuleVersion(p string) (string, string, bool) {
	if matches := r.moduleCacheRe.FindStringSubmatch(p); len(matches) == 4 {
		return matches[1], matches[2], true
	}
	if matches := r.moduleDirRe.FindStringSubmatch(p); len(matches) == 3 {
		return matches[1], matches[2], true
	}
	return "", "", false
}

func goModulePathVariants(module string) []string {
	variants := make(map[string]struct{})
	module = strings.TrimSpace(module)
	if module == "" {
		return nil
	}

	decoded := DecodeGoModulePath(module)
	encoded := encodeGoModulePath(decoded)

	variants[decoded] = struct{}{}
	variants[encoded] = struct{}{}
	variants[module] = struct{}{}

	result := make([]string, 0, len(variants))
	for v := range variants {
		result = append(result, v)
	}
	return result
}

// DecodeGoModulePath decodes Go module path escaping (!u → U) as specified by the module proxy protocol.
func DecodeGoModulePath(module string) string {
	if !strings.Contains(module, "!") {
		return module
	}

	var b strings.Builder
	r := []rune(module)
	for i := 0; i < len(r); i++ {
		if r[i] == '!' && i+1 < len(r) {
			b.WriteRune(rune(strings.ToUpper(string(r[i+1]))[0]))
			i++
			continue
		}
		b.WriteRune(r[i])
	}
	return b.String()
}

func encodeGoModulePath(module string) string {
	var b strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteRune('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
