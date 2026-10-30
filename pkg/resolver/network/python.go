package network

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/sbomit/sbomit/pkg/resolver"
)

// pip fetches from PyPI, conda from its channels.
var (
	pypiNetworkDomains = []string{
		"pypi.org",
		"files.pythonhosted.org",
		"pypi.python.org",
	}
	condaNetworkDomains = []string{
		"conda.anaconda.org",
		"repo.anaconda.com",
		"conda-forge.org",
		"prefix.dev",
	}
)

type PythonNetworkResolver struct {
	// PEP 427 wheel: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
	wheelRe *regexp.Regexp

	// sdist: {name}-{version}.tar.gz (or .zip, .tar.bz2)
	sdistRe *regexp.Regexp

	// The PyPI JSON API: /pypi/{name}/{version}/json.
	apiRe *regexp.Regexp

	// /<channel>/<subdir>/<name>-<version>-<build>.conda (or .tar.bz2)
	condaRe *regexp.Regexp

	condaHosts map[string]struct{}
}

func NewPythonNetworkResolver() *PythonNetworkResolver {
	r := &PythonNetworkResolver{
		wheelRe: regexp.MustCompile(`^([A-Za-z0-9_.]+?)-([0-9][^-]*)(?:-[0-9][^-]*)?-[^-]+-[^-]+-[^-]+\.whl$`),
		sdistRe: regexp.MustCompile(`^(.+)-([0-9][^-]*)\.(?:tar\.gz|zip|tar\.bz2)$`),
		apiRe:   regexp.MustCompile(`^/pypi/([^/]+)/([^/]+)/json$`),
		condaRe: regexp.MustCompile(
			`/([A-Za-z0-9_.-]+?)-([0-9][A-Za-z0-9_.]*)-([A-Za-z0-9_]+)\.(?:conda|tar\.bz2)$`),
		condaHosts: map[string]struct{}{},
	}
	for _, h := range condaNetworkDomains {
		r.condaHosts[h] = struct{}{}
	}
	return r
}

func (r *PythonNetworkResolver) Domains() []string {
	return append(append([]string{}, pypiNetworkDomains...), condaNetworkDomains...)
}

func (r *PythonNetworkResolver) Parse(conn NetworkConnection, ex NetworkExchange) (resolver.PackageInfo, bool, bool) {
	u, err := url.Parse(ex.URL)
	if err != nil {
		return resolver.PackageInfo{}, false, false
	}
	if _, conda := r.condaHosts[conn.Hostname]; conda {
		return r.parseConda(u.Path)
	}
	return r.parsePyPI(u.Path)
}

// parsePyPI reads a distribution from a PyPI request. Wheels and sdists are
// artifacts; the JSON API and PEP 658 .metadata files are not.
func (r *PythonNetworkResolver) parsePyPI(p string) (resolver.PackageInfo, bool, bool) {
	if m := r.apiRe.FindStringSubmatch(p); m != nil {
		return pypiPackage(m[1], m[2]), false, true
	}

	base := path.Base(p)
	artifact := true
	if strings.HasSuffix(base, ".metadata") {
		base = strings.TrimSuffix(base, ".metadata")
		artifact = false
	}

	if m := r.wheelRe.FindStringSubmatch(base); m != nil {
		return pypiPackage(m[1], m[2]), artifact, true
	}
	if m := r.sdistRe.FindStringSubmatch(base); m != nil {
		return pypiPackage(m[1], m[2]), artifact, true
	}
	return resolver.PackageInfo{}, false, false
}

func pypiPackage(name, version string) resolver.PackageInfo {
	name = resolver.NormalizePackageName(name)
	return resolver.PackageInfo{
		Name:      name,
		Version:   version,
		Ecosystem: "pypi",
		PURL:      "pkg:pypi/" + name + "@" + version,
	}
}

// parseConda reads a package from a conda channel download such as
// .../conda-forge/linux-64/numpy-2.1.0-py312h1234567_0.conda. The channel's
// index files (repodata.json, repodata shards) name no single package and are
// not matched.
func (r *PythonNetworkResolver) parseConda(p string) (resolver.PackageInfo, bool, bool) {
	m := r.condaRe.FindStringSubmatch(p)
	if m == nil {
		return resolver.PackageInfo{}, false, false
	}
	name, version, build := m[1], m[2], m[3]

	return resolver.PackageInfo{
		Name:      name,
		Version:   version,
		Ecosystem: "conda",
		PURL:      "pkg:conda/" + name + "@" + version + "?build=" + build,
	}, true, true
}
