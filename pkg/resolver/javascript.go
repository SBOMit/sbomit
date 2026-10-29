package resolver

import (
	"path"
	"regexp"
	"strings"
)

type JavaScriptResolver struct {
	pnpmPathRe  *regexp.Regexp
	yarnCacheRe *regexp.Regexp
	flatNameRe  *regexp.Regexp
}

func NewJavaScriptResolver() *JavaScriptResolver {
	return &JavaScriptResolver{
		// node_modules/.pnpm/<dir>/node_modules/<name>/. The trailing "/" stops
		// a bare scope directory (".../@actions") from matching as a name.
		pnpmPathRe: regexp.MustCompile(`node_modules/\.pnpm/([^/]+)/node_modules/(@[^/]+/[^/]+|[^@/][^/]*)/`),

		// .yarn/cache/<name>-npm-<version>-<locator>-<checksum>.zip, e.g.
		// @actions-cache-npm-6.2.0-687bb8a5bc-b2b3d219d3.zip.
		yarnCacheRe: regexp.MustCompile(
			`/\.yarn/cache/(.+?)-npm-(\d[^-]*(?:-[^-]+)*?)-[0-9a-f]{10}-[0-9a-f]{10}\.zip$`),

		// A scoped name in a flat node_modules tree.
		flatNameRe: regexp.MustCompile(`/node_modules/(@[^/]+/[^/]+)/`),
	}
}

func (r *JavaScriptResolver) Name() string {
	return "javascript"
}

func (r *JavaScriptResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	g := newGroup()

	// Scoped names seen in node_modules, to resolve yarn's flattened scopes.
	knownScoped := map[string]struct{}{}
	for _, f := range files {
		if m := r.flatNameRe.FindStringSubmatch(f.Path); m != nil {
			knownScoped[strings.ToLower(m[1])] = struct{}{}
		}
	}

	for _, f := range files {
		np := path.Clean(f.Path)

		if !r.isJavaScriptPath(np) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		name, version, pkgmgr, ok := r.identify(np, knownScoped)
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
			PkgMgr:    pkgmgr,
		}, f)
	}

	// No artifact: pnpm keeps extracted files, and yarn's cache zip is yarn's
	// repack of the npm tarball.
	packages, rest := g.finish(rankNpmEvidence, nil)
	return packages, append(remainingFiles, rest...)
}

// identify returns the package a JavaScript path belongs to, and the package
// manager whose path it is.
func (r *JavaScriptResolver) identify(p string, knownScoped map[string]struct{}) (string, string, string, bool) {
	if m := r.yarnCacheRe.FindStringSubmatch(p); m != nil {
		return unflattenYarnScope(m[1], knownScoped), m[2], "yarn", true
	}
	name, version, ok := r.extractPnpmPackage(p)
	return name, version, "pnpm", ok
}

// unflattenYarnScope recovers "@scope/name" from yarn's ambiguous
// "@scope-name" by matching scoped names seen in node_modules. Unconfirmed
// names are kept as-is rather than guessed.
func unflattenYarnScope(stem string, knownScoped map[string]struct{}) string {
	if !strings.HasPrefix(stem, "@") {
		return stem
	}

	body := stem[1:]
	for i, ch := range body {
		if ch != '-' {
			continue
		}
		candidate := "@" + body[:i] + "/" + body[i+1:]
		if _, found := knownScoped[strings.ToLower(candidate)]; found {
			return candidate
		}
	}

	return stem
}

// rankNpmEvidence prefers package.json.
func rankNpmEvidence(p string) int {
	if path.Base(p) == "package.json" {
		return 1
	}
	return 0
}

func (r *JavaScriptResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter

	// A flat node_modules path has no version, so it is attributed only when
	// one version of the name was resolved.
	versionsByName := map[string]int{}
	for _, pkg := range packages {
		if pkg.Ecosystem == "npm" {
			versionsByName[strings.ToLower(pkg.Name)]++
		}
	}

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
		yarnNeedle := "/.yarn/cache/" + strings.ReplaceAll(strings.TrimPrefix(name, "@"), "/", "-") +
			"-npm-" + ver + "-"
		unambiguous := versionsByName[name] == 1

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				if strings.Contains(p.Lower, "/node_modules/.pnpm/") {
					return strings.Contains(p.Lower, pnpmNeedle) &&
						strings.Contains(p.Lower, nameNeedle)
				}
				if strings.Contains(p.Lower, "/.yarn/cache/") {
					return strings.Contains(p.Lower, yarnNeedle)
				}
				return unambiguous && strings.Contains(p.Lower, nameNeedle)
			}),
		})
	}

	return filters
}

func (r *JavaScriptResolver) isJavaScriptPath(p string) bool {
	return strings.Contains(p, "node_modules") ||
		strings.Contains(p, ".pnpm") ||
		strings.Contains(p, "/.yarn/")
}

// extractPnpmPackage identifies the package of a pnpm store path. The store
// directory also links the package's dependencies:
//
//	.pnpm/@actions+cache@4.1.0/node_modules/@actions/cache/...  <- the package
//	.pnpm/@actions+cache@4.1.0/node_modules/@actions/core/...   <- a dependency
//
// so the inner name must match the directory's name.
func (r *JavaScriptResolver) extractPnpmPackage(p string) (string, string, bool) {
	matches := r.pnpmPathRe.FindStringSubmatch(p)
	if len(matches) != 3 {
		return "", "", false
	}

	dirName, version := splitPnpmStoreDir(matches[1])
	if version == "" {
		return "", "", false
	}

	name := matches[2]
	if !strings.EqualFold(dirName, name) {
		return "", "", false
	}

	return name, version, true
}

// splitPnpmStoreDir splits a pnpm store directory name into the package name
// and version it encodes.
//
//	"@actions+cache@4.1.0"              -> "@actions/cache", "4.1.0"
//	"debug@4.4.3(supports-color@8.1.1)" -> "debug", "4.4.3"
//
// The separator is the last "@"; the parenthesised peer-dependency suffix is
// not part of the version.
func splitPnpmStoreDir(segment string) (name, version string) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return "", ""
	}

	if idx := strings.Index(segment, "("); idx != -1 {
		segment = segment[:idx]
	}

	lastAt := strings.LastIndex(segment, "@")
	if lastAt <= 0 || lastAt == len(segment)-1 {
		return "", ""
	}

	// pnpm flattens the scope separator to "+": @actions+cache.
	return strings.ReplaceAll(segment[:lastAt], "+", "/"), segment[lastAt+1:]
}

// NormalizeNpmPackageName lowercases and trims an npm package name.
func NormalizeNpmPackageName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	return name
}
