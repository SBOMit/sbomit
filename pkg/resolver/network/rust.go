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
	// Matches static.crates.io's download endpoint, which has no filename:
	// /crates/{name}/{version}/download
	downloadRe *regexp.Regexp
}

func NewRustNetworkResolver() *RustNetworkResolver {
	return &RustNetworkResolver{
		crateRe:    regexp.MustCompile(`^/crates/([^/]+)/[^/]+-([0-9][A-Za-z0-9._-]*)\.crate$`),
		apiRe:      regexp.MustCompile(`^/api/v1/crates/([^/]+)/([0-9][A-Za-z0-9._-]*)/download$`),
		downloadRe: regexp.MustCompile(`^/crates/([^/]+)/([0-9][A-Za-z0-9._+-]*)/download$`),
	}
}

func (r *RustNetworkResolver) Domains() []string {
	return rustNetworkDomains
}

// Parse reads a crate from a download request; index lookups are ignored.
func (r *RustNetworkResolver) Parse(_ NetworkConnection, ex NetworkExchange) (resolver.PackageInfo, bool, bool) {
	name, version, ok := r.parseURL(ex.URL)
	if !ok {
		return resolver.PackageInfo{}, false, false
	}

	name = resolver.NormalizeRustCrateName(name)
	return resolver.PackageInfo{
		Name:      name,
		Version:   version,
		Ecosystem: "cargo",
		PURL:      "pkg:cargo/" + name + "@" + version,
	}, true, true
}

func (r *RustNetworkResolver) parseURL(rawURL string) (name, version string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}

	// Tried first: the other shapes share its /crates/<name>/ prefix.
	if matches := r.downloadRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return resolver.NormalizeRustCrateName(matches[1]), matches[2], true
	}

	if matches := r.crateRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return resolver.NormalizeRustCrateName(matches[1]), matches[2], true
	}

	if matches := r.apiRe.FindStringSubmatch(u.Path); len(matches) == 3 {
		return resolver.NormalizeRustCrateName(matches[1]), matches[2], true
	}

	return "", "", false
}
