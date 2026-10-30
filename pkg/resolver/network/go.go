package network

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/sbomit/sbomit/pkg/resolver"
)

// Go module proxy domains.
// storage.googleapis.com is the CDN backend used by proxy.golang.org; the
// Referer header on those requests carries the canonical proxy.golang.org URL.
var goNetworkDomains = []string{
	"proxy.golang.org",
	"storage.googleapis.com",
}

type GoNetworkResolver struct {
	// Matches /{module}/@v/{version}.{ext}
	// e.g. /github.com/cilium/ebpf/@v/v0.20.0.zip
	proxyPathRe *regexp.Regexp
}

func NewGoNetworkResolver() *GoNetworkResolver {
	return &GoNetworkResolver{
		proxyPathRe: regexp.MustCompile(`^/(.+)/@v/([^/]+)\.(zip|mod|info)$`),
	}
}

func (r *GoNetworkResolver) Domains() []string {
	return goNetworkDomains
}

// Parse reads a module from a proxy request. Only the .zip is the artifact;
// .info and .mod are metadata.
func (r *GoNetworkResolver) Parse(conn NetworkConnection, ex NetworkExchange) (resolver.PackageInfo, bool, bool) {
	// Redirected zips: the Referer holds the proxy URL.
	urlToParse := ex.URL
	if conn.Hostname == "storage.googleapis.com" && strings.Contains(ex.Referer, "proxy.golang.org") {
		urlToParse = ex.Referer
	}

	module, version, ext, ok := r.parseProxyURL(urlToParse)
	if !ok {
		return resolver.PackageInfo{}, false, false
	}

	return resolver.PackageInfo{
		Name:      module,
		Version:   version,
		Ecosystem: "golang",
		PURL:      resolver.GoPURL(module, version),
	}, ext == "zip", true
}

func (r *GoNetworkResolver) parseProxyURL(rawURL string) (module, version, ext string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", false
	}

	matches := r.proxyPathRe.FindStringSubmatch(u.Path)
	if len(matches) != 4 {
		return "", "", "", false
	}

	return resolver.DecodeGoModulePath(matches[1]), matches[2], matches[3], true
}
