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
	g := newGroup()

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
		g.add(name+"@"+version, PackageInfo{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
			PURL:      "pkg:npm/" + name + "@" + version,
			FoundBy:   "attestation:javascript",
		}, f)
	}

	packages, rest := g.finish(rankNpmEvidence)
	return packages, append(remainingFiles, rest...)
}

// rankNpmEvidence prefers package.json, the manifest that declares the
// package's name and version.
func rankNpmEvidence(p string) int {
	if path.Base(p) == "package.json" {
		return 1
	}
	return 0
}

func (r *JavaScriptResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "npm" {
			continue
		}

		name := strings.ToLower(pkg.Name)
		ver := strings.ToLower(pkg.Version)
		if name == "" || ver == "" {
			continue
		}

		// Precomputed, so matching doesn't concatenate on every comparison.
		pnpmNeedle := "/node_modules/.pnpm/" + strings.ReplaceAll(name, "/", "+") + "@" + ver
		nameNeedle := "/node_modules/" + name + "/"

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				if !strings.Contains(p.Lower, "/node_modules/.pnpm/") {
					return false
				}
				return strings.Contains(p.Lower, pnpmNeedle) &&
					strings.Contains(p.Lower, nameNeedle)
			}),
		})
	}

	return filters
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
