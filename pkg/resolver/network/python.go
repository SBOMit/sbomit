package network

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/sbomit/sbomit/pkg/resolver"
)

// Python package distribution domains.
var pythonNetworkDomains = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"pypi.python.org",
}

type PythonNetworkResolver struct {
	// Matches wheel/sdist filenames: {name}-{version}[-...].whl or {name}-{version}.tar.gz
	// e.g. /packages/.../requests-2.31.0-py3-none-any.whl
	fileRe *regexp.Regexp
	// Matches the PyPI JSON API path: /pypi/{name}/{version}/json
	apiRe *regexp.Regexp
}

func NewPythonNetworkResolver() *PythonNetworkResolver {
	return &PythonNetworkResolver{
		fileRe: regexp.MustCompile(`/([A-Za-z0-9_.-]+)-([0-9][A-Za-z0-9._+]*?)(?:-py[0-9]|-cp[0-9]|\.tar\.gz|\.zip|\.whl)`),
		apiRe:  regexp.MustCompile(`^/pypi/([^/]+)/([^/]+)/json$`),
	}
}

func (r *PythonNetworkResolver) Domains() []string {
	return pythonNetworkDomains
}

func (r *PythonNetworkResolver) Resolve(conn NetworkConnection) []resolver.PackageInfo {
	seen := make(map[string]struct{})
	var packages []resolver.PackageInfo

	for _, ex := range conn.Exchanges {
		if !isSuccessful(ex.StatusCode) {
			continue
		}

		name, version, ok := r.parseURL(ex.URL)
		if !ok {
			continue
		}

		purl := "pkg:pypi/" + name + "@" + version
		if _, already := seen[purl]; already {
			continue
		}
		seen[purl] = struct{}{}

		pkg := resolver.PackageInfo{
			Name:        name,
			Version:     version,
			Ecosystem:   "pypi",
			PURL:        purl,
			FoundBy:     "network:python",
			DownloadURL: ex.URL,
			DownloadIP:  conn.IP,
		}
		if ex.BodyHash != "" {
			pkg.Hashes = map[string]string{"sha256": ex.BodyHash}
		}
		packages = append(packages, pkg)
	}

	return packages
}

func (r *PythonNetworkResolver) parseURL(rawURL string) (name, version string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}

	// PyPI JSON API: /pypi/{name}/{version}/json
	if matches := r.apiRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return resolver.NormalizePackageName(matches[1]), matches[2], true
	}

	// Wheel or sdist filename in the path
	if matches := r.fileRe.FindStringSubmatch(u.Path); len(matches) >= 3 {
		v := matches[2]
		// Strip trailing ".tar" that the regex may capture before ".gz"
		v = strings.TrimSuffix(v, ".tar")
		return resolver.NormalizePackageName(matches[1]), v, true
	}

	return "", "", false
}
