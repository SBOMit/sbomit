package network

import (
	"net/url"
	"regexp"

	"github.com/sbomit/sbomit/pkg/resolver"
)

// JavaScript/npm package registry domains.
var jsNetworkDomains = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
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

// Parse reads a package from a registry request: the .tgz is the artifact,
// /<name>/<version> is metadata.
func (r *JavaScriptNetworkResolver) Parse(_ NetworkConnection, ex NetworkExchange) (resolver.PackageInfo, bool, bool) {
	u, err := url.Parse(ex.URL)
	if err != nil {
		return resolver.PackageInfo{}, false, false
	}

	name, version, artifact := "", "", false
	if m := r.tgzRe.FindStringSubmatch(u.Path); len(m) == 3 {
		name, version, artifact = m[1], m[2], true
	} else if m := r.metaRe.FindStringSubmatch(u.Path); len(m) == 3 {
		name, version = m[1], m[2]
	} else {
		return resolver.PackageInfo{}, false, false
	}

	name = resolver.NormalizeNpmPackageName(name)
	return resolver.PackageInfo{
		Name:      name,
		Version:   version,
		Ecosystem: "npm",
		PURL:      "pkg:npm/" + name + "@" + version,
	}, artifact, true
}
