package network

import (
	"net/url"
	"regexp"

	"github.com/sbomit/sbomit/pkg/resolver"
)

// JavaScript/npm package registry domains.
var jsNetworkDomains = []string{
	"registry.npmjs.org",
	"npm.pkg.github.com",
}

type JavaScriptNetworkResolver struct {
	// Matches tarball downloads:
	//   non-scoped: /lodash/-/lodash-4.17.21.tgz
	//   scoped:     /@babel/core/-/core-7.24.0.tgz
	tgzRe *regexp.Regexp
	// Matches metadata endpoint:
	//   non-scoped: /lodash/4.17.21
	//   scoped:     /@babel/core/7.24.0
	metaRe *regexp.Regexp
}

func NewJavaScriptNetworkResolver() *JavaScriptNetworkResolver {
	return &JavaScriptNetworkResolver{
		tgzRe:  regexp.MustCompile(`^/(@[^/]+/[^/]+|[^/]+)/-/[^/]+-([0-9][A-Za-z0-9._-]*)\.tgz$`),
		metaRe: regexp.MustCompile(`^/(@[^/]+/[^/]+|[^/]+)/([0-9][A-Za-z0-9._-]*)$`),
	}
}

func (r *JavaScriptNetworkResolver) Domains() []string {
	return jsNetworkDomains
}

func (r *JavaScriptNetworkResolver) Resolve(conn NetworkConnection) []resolver.PackageInfo {
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

		purl := "pkg:npm/" + name + "@" + version
		if _, already := seen[purl]; already {
			continue
		}
		seen[purl] = struct{}{}

		pkg := resolver.PackageInfo{
			Name:        name,
			Version:     version,
			Ecosystem:   "npm",
			PURL:        purl,
			FoundBy:     "network:javascript",
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

func (r *JavaScriptNetworkResolver) parseURL(rawURL string) (name, version string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}

	if matches := r.tgzRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return resolver.NormalizeNpmPackageName(matches[1]), matches[2], true
	}

	if matches := r.metaRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return resolver.NormalizeNpmPackageName(matches[1]), matches[2], true
	}

	return "", "", false
}
