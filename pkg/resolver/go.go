package resolver

import (
	"net/url"
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
		moduleCacheRe: regexp.MustCompile(`pkg/mod/cache/download/(.+)/@v/([^/]+)\.(mod|zip|info|ziphash)`),
	}
}

func (r *GoResolver) Name() string {
	return "go"
}

func (r *GoResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	g := newGroup()

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
		g.add(module+"@"+version, PackageInfo{
			Name:      module,
			Version:   version,
			Ecosystem: "golang",
			PURL:      "pkg:golang/" + module + "@" + encodeGoPURLVersion(version),
			FoundBy:   "attestation:go",
		}, f)
	}

	packages, rest := g.finish(rankGoEvidence)
	return packages, append(remainingFiles, rest...)
}

// rankGoEvidence prefers the module zip: it is the distributed artifact, so it
// is the strongest evidence that the module was used.
func rankGoEvidence(p string) int {
	switch {
	case strings.HasSuffix(p, ".zip"):
		return 3
	case strings.HasSuffix(p, ".info"), strings.HasSuffix(p, ".mod"):
		return 2
	case strings.Contains(p, "/pkg/mod/cache/download/"):
		return 1
	default:
		return 0
	}
}

func (r *GoResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "golang" {
			continue
		}

		// Precomputed, so matching doesn't concatenate on every comparison.
		version := strings.ToLower(pkg.Version)
		variants := goModulePathVariants(pkg.Name)
		needles := make([]string, 0, len(variants)*2)
		for _, v := range variants {
			vl := strings.ToLower(v)
			needles = append(needles,
				"/pkg/mod/"+vl+"@"+version+"/",
				"/pkg/mod/cache/download/"+vl+"/@v/"+version+".",
			)
		}

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				if !strings.Contains(p.Lower, "/pkg/mod/") {
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

func encodeGoPURLVersion(version string) string {
	return strings.ReplaceAll(url.PathEscape(version), "+", "%2B")
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
