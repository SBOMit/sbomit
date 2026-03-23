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

func (r *GoNetworkResolver) Resolve(conn NetworkConnection) []resolver.PackageInfo {
	seen := make(map[string]struct{})
	var packages []resolver.PackageInfo

	for _, ex := range conn.Exchanges {
		if !isSuccessful(ex.StatusCode) {
			continue
		}

		// storage.googleapis.com serves Go module zips redirected from the proxy.
		// The Referer header holds the original proxy.golang.org URL, which is
		// also the canonical URL to record.
		urlToParse := ex.URL
		downloadURL := ex.URL
		if conn.Hostname == "storage.googleapis.com" && strings.Contains(ex.Referer, "proxy.golang.org") {
			urlToParse = ex.Referer
			downloadURL = ex.Referer
		}

		module, version, ok := r.parseProxyURL(urlToParse)
		if !ok {
			continue
		}

		purl := "pkg:golang/" + module + "@" + version
		if _, already := seen[purl]; already {
			continue
		}
		seen[purl] = struct{}{}

		pkg := resolver.PackageInfo{
			Name:        module,
			Version:     version,
			Ecosystem:   "golang",
			PURL:        purl,
			FoundBy:     "network:go",
			DownloadURL: downloadURL,
			DownloadIP:  conn.IP,
		}
		if ex.BodyHash != "" {
			pkg.Hashes = map[string]string{"sha256": ex.BodyHash}
		}
		packages = append(packages, pkg)
	}

	return packages
}

func (r *GoNetworkResolver) parseProxyURL(rawURL string) (module, version string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}

	matches := r.proxyPathRe.FindStringSubmatch(u.Path)
	if len(matches) < 3 {
		return "", "", false
	}

	return resolver.DecodeGoModulePath(matches[1]), matches[2], true
}
