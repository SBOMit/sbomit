package resolver

import (
	"path"
	"regexp"
	"strings"
)

// PythonResolver resolves Python's package managers: pip (site-packages) and
// conda (package cache and environment prefixes). Conda packages keep the
// pkg:conda PURL type, since many are not PyPI distributions.
//
// Conda is matched first: its packages can contain a site-packages directory
// that the pip pass would otherwise report as PyPI.
type PythonResolver struct {
	metadataPattern *regexp.Regexp
	wheelPattern    *regexp.Regexp
	conda           *condaLayout
}

func NewPythonResolver() *PythonResolver {
	return &PythonResolver{
		// site-packages/<name>-<version>.dist-info, or the legacy
		// <name>-<version>-pyX.Y.egg-info. The optional -pyX.Y is a Python
		// tag, not part of the version.
		metadataPattern: regexp.MustCompile(`(?:dist-packages|site-packages)/([^/]+?)-([0-9][0-9A-Za-z\.\+_]*)(?:-py[0-9]+\.[0-9]+)?\.(dist-info|egg-info)`),

		// A wheel pip downloaded and staged in pip-unpack-*/. Wheels elsewhere
		// (dist/, pip's wheel cache) were built locally, not downloaded.
		wheelPattern: regexp.MustCompile(
			`/pip-unpack-[^/]+/([A-Za-z0-9_.]+?)-([0-9][0-9A-Za-z.+_]*)-[^/-]+-[^/-]+-[^/-]+\.whl$`),

		conda: newCondaLayout(),
	}
}

func (r *PythonResolver) Name() string {
	return "python"
}

func (r *PythonResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	// Files conda claimed skip the pip pass, but are still returned for
	// attribution.
	condaPackages, claimed, unclaimed := r.conda.resolve(files)
	pipPackages, remainingFiles := r.resolvePip(unclaimed)
	return append(condaPackages, pipPackages...), append(remainingFiles, claimed...)
}

// resolvePip resolves site-packages installs and staged wheels.
func (r *PythonResolver) resolvePip(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	g := newGroup()

	for _, f := range files {
		np := path.Clean(f.Path)

		if !r.isPythonPath(np) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		name, version, ok := r.identify(np)
		if !ok {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		g.add(name+"@"+version, PackageInfo{
			Name:      name,
			Version:   version,
			Ecosystem: "pypi",
			PURL:      "pkg:pypi/" + name + "@" + version,
			// uv and poetry write the same site-packages paths as pip.
			PkgMgr: "pip",
		}, f)
	}

	packages, rest := g.finish(rankPythonEvidence, isPythonWheel)
	return packages, append(remainingFiles, rest...)
}

// identify returns the distribution a Python path belongs to.
func (r *PythonResolver) identify(p string) (string, string, bool) {
	if m := r.metadataPattern.FindStringSubmatch(p); len(m) >= 4 {
		return NormalizePackageName(m[1]), m[2], true
	}
	if m := r.wheelPattern.FindStringSubmatch(p); len(m) == 3 {
		// Wheel names escape "-" as "_"; normalization undoes it.
		return NormalizePackageName(m[1]), m[2], true
	}
	return "", "", false
}

// isPythonWheel reports whether a path is a wheel pip downloaded.
func isPythonWheel(p string) bool {
	return strings.HasSuffix(strings.ToLower(p), ".whl") &&
		strings.Contains(p, "/pip-unpack-")
}

// rankPythonEvidence prefers METADATA/PKG-INFO, then the staged wheel, then
// other files. RECORD, WHEEL and INSTALLER are installer boilerplate.
func rankPythonEvidence(p string) int {
	switch strings.ToUpper(path.Base(p)) {
	case "METADATA", "PKG-INFO":
		return 3
	case "RECORD", "WHEEL", "INSTALLER":
		return 0
	}

	if isPythonWheel(p) {
		return 2
	}
	return 1
}

// OwnershipFilters attributes files under a package's directory to it.
func (r *PythonResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	filters := r.conda.ownershipFilters(packages)

	for _, pkg := range packages {
		if pkg.Ecosystem != "pypi" {
			continue
		}

		// Precomputed, so matching doesn't concatenate on every comparison.
		variants := getPythonPackageDirVariants(pkg.Name)
		needles := make([]string, 0, len(variants)*4)
		wheelNeedles := make([]string, 0, len(variants))
		for _, v := range variants {
			needles = append(needles,
				"/site-packages/"+v+"/",
				"/dist-packages/"+v+"/",
				"/site-packages/"+v+"-",
				"/dist-packages/"+v+"-",
			)
			// A wheel filename escapes "-" in the name as "_".
			wheelNeedles = append(wheelNeedles,
				"/"+strings.ReplaceAll(v, "-", "_")+"-"+strings.ToLower(pkg.Version)+"-")
		}

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				// The staged wheel lives outside site-packages.
				if isPythonWheel(p.Clean) {
					for _, n := range wheelNeedles {
						if strings.Contains(p.Lower, n) {
							return true
						}
					}
					return false
				}

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
		strings.Contains(p, ".dist-info") ||
		isPythonWheel(p)
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

// condaLayout recognizes what conda leaves on disk:
//
//	<cache root>/<name>-<version>-<build>.conda           the downloaded artifact
//	<cache root>/<name>-<version>-<build>/info/index.json the extracted package
//	<prefix>/conda-meta/<name>-<version>-<build>.json     an environment's install record
//
// The build string is part of a conda package's identity, so it is kept as a
// PURL qualifier.
type condaLayout struct {
	// Finds cache roots by their info/ directories, since CONDA_PKGS_DIRS can
	// point anywhere.
	infoRe *regexp.Regexp

	// <cache root>/<name>-<version>-<build>.conda, or the older .tar.bz2.
	archiveRe *regexp.Regexp

	// <prefix>/conda-meta/<name>-<version>-<build>.json, one per installed package.
	metaRe *regexp.Regexp

	// <prefix>/lib/pythonX.Y/site-packages/<name>-<version>.{dist,egg}-info/.
	sitePackagesRe *regexp.Regexp
}

func newCondaLayout() *condaLayout {
	return &condaLayout{
		infoRe:    regexp.MustCompile(`^(.*)/([^/]+)-([0-9][A-Za-z0-9_.]*)-([A-Za-z0-9_]+)/info/index\.json$`),
		archiveRe: regexp.MustCompile(`^(.*)/([^/]+)-([0-9][A-Za-z0-9_.]*)-([A-Za-z0-9_]+)\.(?:conda|tar\.bz2)$`),
		metaRe:    regexp.MustCompile(`^(.*)/conda-meta/([^/]+)-([0-9][A-Za-z0-9_.]*)-([A-Za-z0-9_]+)\.json$`),
		sitePackagesRe: regexp.MustCompile(
			`^(.*)/lib/python[0-9.]+/site-packages/([^/]+?)-([0-9][0-9A-Za-z.+_]*)(?:-py[0-9]+\.[0-9]+)?\.(?:dist|egg)-info(?:/|$)`),
	}
}

// condaPkg is one conda package: name, version and build string.
type condaPkg struct {
	name    string
	version string
	build   string
}

func (c condaPkg) purl() string {
	return "pkg:conda/" + c.name + "@" + c.version + "?build=" + c.build
}

func (c condaPkg) info() PackageInfo {
	return PackageInfo{
		Name:      c.name,
		Version:   c.version,
		Ecosystem: "conda",
		PURL:      c.purl(),
		PkgMgr:    "conda",
	}
}

// pythonNames are the distribution names a conda package may install under;
// conda-forge sometimes renames (msgpack-python provides msgpack).
func (c condaPkg) pythonNames() []string {
	n := NormalizePackageName(c.name)
	names := []string{n}
	if s := strings.TrimSuffix(n, "-python"); s != n {
		names = append(names, s)
	}
	if s := strings.TrimPrefix(n, "python-"); s != n {
		names = append(names, s)
	}
	return names
}

// resolve returns conda's packages, the other files it claimed, and the files
// it did not claim.
func (l *condaLayout) resolve(files []FileInfo) (packages []PackageInfo, claimed, unclaimed []FileInfo) {
	// Pass 1: find cache roots, their packages, and each prefix's records.
	roots := map[string]struct{}{}
	byDir := map[string]condaPkg{}
	byPrefix := map[string]map[string]condaPkg{} // prefix -> "<pypi name>@<version>" -> package
	fromCache := map[string]condaPkg{}           // "<pypi name>@<version>" -> package

	for _, f := range files {
		p := path.Clean(f.Path)
		if m := l.infoRe.FindStringSubmatch(p); m != nil {
			pkg := condaPkg{m[2], m[3], m[4]}
			roots[m[1]] = struct{}{}
			byDir[m[1]+"/"+m[2]+"-"+m[3]+"-"+m[4]] = pkg
			for _, n := range pkg.pythonNames() {
				fromCache[n+"@"+pkg.version] = pkg
			}
		}
		if m := l.metaRe.FindStringSubmatch(p); m != nil {
			pkg := condaPkg{m[2], m[3], m[4]}
			if byPrefix[m[1]] == nil {
				byPrefix[m[1]] = map[string]condaPkg{}
			}
			for _, n := range pkg.pythonNames() {
				byPrefix[m[1]][n+"@"+pkg.version] = pkg
			}
		}
	}

	if len(roots) == 0 && len(byPrefix) == 0 {
		return nil, nil, files
	}

	// Pass 2: claim conda's files. The rest, including pip installs into a
	// conda environment, goes to the pip pass.
	g := newGroup()
	for _, f := range files {
		pkg, ok := l.identify(path.Clean(f.Path), roots, byDir, byPrefix, fromCache)
		if !ok {
			unclaimed = append(unclaimed, f)
			continue
		}
		g.add(pkg.purl(), pkg.info(), f)
	}

	packages, claimed = g.finish(rankCondaEvidence, isCondaArtifact)
	return packages, claimed, unclaimed
}

// identify reports which conda package a path belongs to.
func (l *condaLayout) identify(p string, roots map[string]struct{}, byDir map[string]condaPkg,
	byPrefix map[string]map[string]condaPkg, fromCache map[string]condaPkg) (condaPkg, bool) {

	if m := l.archiveRe.FindStringSubmatch(p); m != nil {
		if _, ok := roots[m[1]]; ok {
			return condaPkg{m[2], m[3], m[4]}, true
		}
	}

	if m := l.metaRe.FindStringSubmatch(p); m != nil {
		return condaPkg{m[2], m[3], m[4]}, true
	}

	// A file inside an extracted package: the package is the segment right
	// below the cache root. (A pattern would also match nested dirs such as
	// msgpack-1.2.3.dist-info/.)
	for root := range roots {
		if !strings.HasPrefix(p, root+"/") {
			continue
		}
		seg := strings.SplitN(p[len(root)+1:], "/", 2)[0]
		if pkg, known := byDir[root+"/"+seg]; known {
			return pkg, true
		}
	}

	// A dist-info in a prefix belongs to conda if that prefix's records (or,
	// without records, the cache) list the package.
	if m := l.sitePackagesRe.FindStringSubmatch(p); m != nil {
		key := NormalizePackageName(m[2]) + "@" + m[3]
		if records, ok := byPrefix[m[1]]; ok {
			pkg, provided := records[key]
			return pkg, provided
		}
		pkg, provided := fromCache[key]
		return pkg, provided
	}

	return condaPkg{}, false
}

// isCondaArtifact reports whether a path is the artifact the channel published.
func isCondaArtifact(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, ".conda") || strings.HasSuffix(lower, ".tar.bz2")
}

// rankCondaEvidence prefers the artifact, then index.json or the install record.
func rankCondaEvidence(p string) int {
	switch {
	case isCondaArtifact(p):
		return 3
	case strings.HasSuffix(p, "/info/index.json"), strings.Contains(p, "/conda-meta/"):
		return 2
	case strings.Contains(p, "/info/"):
		return 0
	default:
		return 1
	}
}

func (l *condaLayout) ownershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "conda" {
			continue
		}

		build := ""
		if i := strings.Index(pkg.PURL, "?build="); i != -1 {
			build = pkg.PURL[i+len("?build="):]
		}
		if build == "" {
			continue
		}

		// The extracted directory and the artifact, under any cache root.
		dirNeedle := "/" + strings.ToLower(pkg.Name) + "-" + strings.ToLower(pkg.Version) + "-" +
			strings.ToLower(build) + "/"
		archiveNeedle := strings.TrimSuffix(dirNeedle, "/") + "."

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				return strings.Contains(p.Lower, dirNeedle) ||
					strings.Contains(p.Lower, archiveNeedle)
			}),
		})
	}

	return filters
}
