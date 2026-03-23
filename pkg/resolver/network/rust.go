package network

import (
	"net/url"
	"regexp"

	"github.com/sbomit/sbomit/pkg/resolver"
)

// Rust crate registry domains.
var rustNetworkDomains = []string{
	"crates.io",
	"static.crates.io",
	"index.crates.io",
}

type RustNetworkResolver struct {
	// Matches static download path: /crates/{name}/{name}-{version}.crate
	crateRe *regexp.Regexp
	// Matches API download endpoint: /api/v1/crates/{name}/{version}/download
	apiRe *regexp.Regexp
}

func NewRustNetworkResolver() *RustNetworkResolver {
	return &RustNetworkResolver{
		crateRe: regexp.MustCompile(`^/crates/([^/]+)/[^/]+-([0-9][A-Za-z0-9._-]*)\.crate$`),
		apiRe:   regexp.MustCompile(`^/api/v1/crates/([^/]+)/([0-9][A-Za-z0-9._-]*)/download$`),
	}
}

func (r *RustNetworkResolver) Domains() []string {
	return rustNetworkDomains
}

func (r *RustNetworkResolver) Resolve(conn NetworkConnection) []resolver.PackageInfo {
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

		name = resolver.NormalizeRustCrateName(name)
		purl := "pkg:cargo/" + name + "@" + version
		if _, already := seen[purl]; already {
			continue
		}
		seen[purl] = struct{}{}

		pkg := resolver.PackageInfo{
			Name:        name,
			Version:     version,
			Ecosystem:   "cargo",
			PURL:        purl,
			FoundBy:     "network:rust",
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

func (r *RustNetworkResolver) parseURL(rawURL string) (name, version string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}

	if matches := r.crateRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return matches[1], matches[2], true
	}

	if matches := r.apiRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return matches[1], matches[2], true
	}

	return "", "", false
}
