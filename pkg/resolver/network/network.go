// Package network reads packages from network-trace request URLs. Each
// ecosystem registers its hostnames and URL parsing; every request that names
// a package is reported, artifact or metadata.
package network

import (
	"sort"
	"strings"

	"github.com/sbomit/sbomit/pkg/attestation"
	"github.com/sbomit/sbomit/pkg/resolver"
)

// NetworkConnection is a single tracked connection from a network-trace attestation.
type NetworkConnection struct {
	Hostname  string
	IP        string
	Protocol  string
	Exchanges []NetworkExchange
}

// NetworkExchange is one HTTP request/response pair within a connection.
type NetworkExchange struct {
	URL        string
	Method     string
	Referer    string
	UserAgent  string
	StatusCode int
	BodyHash   string
}

// Download is one request that named a package.
type Download struct {
	// Package is the identity in the URL; PkgMgr is the package manager that
	// made the request.
	Package resolver.PackageInfo

	URL string

	// Artifact reports whether the response was the package's artifact.
	Artifact bool

	// Digests of the response body.
	Digests []resolver.Digest
}

// DomainResolver reads packages from requests to its hostnames.
type DomainResolver interface {
	// Domains returns the hostnames this resolver handles.
	Domains() []string

	// Parse returns the package a request names and whether the response was
	// its artifact; ok is false if it names none.
	Parse(conn NetworkConnection, ex NetworkExchange) (pkg resolver.PackageInfo, artifact, ok bool)
}

// Chain routes connections to the appropriate DomainResolver by hostname.
type Chain struct {
	byDomain map[string]DomainResolver
}

// NewChain builds a Chain with all built-in ecosystem resolvers registered.
func NewChain() *Chain {
	c := &Chain{byDomain: make(map[string]DomainResolver)}
	for _, r := range []DomainResolver{
		NewGoNetworkResolver(),
		NewPythonNetworkResolver(),
		NewJavaScriptNetworkResolver(),
		NewRustNetworkResolver(),
		NewJavaNetworkResolver(),
	} {
		for _, d := range r.Domains() {
			c.byDomain[d] = r
		}
	}
	return c
}

// ResolveAll returns one Download per distinct (package, URL), sorted.
func (c *Chain) ResolveAll(conns []NetworkConnection) []Download {
	index := make(map[string]int)
	var downloads []Download

	for _, conn := range conns {
		dr, ok := c.byDomain[conn.Hostname]
		if !ok {
			continue
		}
		for _, ex := range conn.Exchanges {
			if !isSuccessful(ex.StatusCode) {
				continue
			}
			pkg, artifact, ok := dr.Parse(conn, ex)
			if !ok || pkg.PURL == "" {
				continue
			}
			pkg.PkgMgr = clientPkgMgr(ex.UserAgent, conn.Hostname)

			digests := attestation.AddDigest(nil, "sha256", ex.BodyHash)

			key := pkg.PURL + "\x00" + ex.URL
			if i, seen := index[key]; seen {
				downloads[i].Digests = attestation.MergeDigests(downloads[i].Digests, digests)
				attestation.SortDigests(downloads[i].Digests)
				continue
			}
			index[key] = len(downloads)
			downloads = append(downloads, Download{
				Package:  pkg,
				URL:      ex.URL,
				Artifact: artifact,
				Digests:  digests,
			})
		}
	}

	sort.SliceStable(downloads, func(i, j int) bool {
		if downloads[i].Package.PURL != downloads[j].Package.PURL {
			return downloads[i].Package.PURL < downloads[j].Package.PURL
		}
		return downloads[i].URL < downloads[j].URL
	})
	return downloads
}

// clientPkgMgr names the requesting package manager from its User-Agent.
// Yarn berry sends "got", so its registry host identifies it instead.
func clientPkgMgr(userAgent, hostname string) string {
	ua := strings.ToLower(userAgent)
	for _, m := range []struct{ prefix, pkgmgr string }{
		{"pnpm/", "pnpm"},
		{"npm/", "npm"},
		{"yarn/", "yarn"},
		{"pip/", "pip"},
		{"uv/", "uv"},
		{"conda/", "conda"},
		{"cargo/", "cargo"},
		{"go-http-client/", "go"},
		{"apache-maven/", "maven"},
		{"gradle/", "gradle"},
	} {
		if strings.HasPrefix(ua, m.prefix) {
			return m.pkgmgr
		}
	}
	if hostname == "registry.yarnpkg.com" {
		return "yarn"
	}
	return ""
}

// ExtractConnections pulls NetworkConnection values from network-trace attestations.
func ExtractConnections(attestations []attestation.TypedAttestation) []NetworkConnection {
	var conns []NetworkConnection
	for _, att := range attestations {
		if att.Type != "network-trace" {
			continue
		}
		conns = append(conns, extractFromData(att.Data)...)
	}
	return conns
}

func extractFromData(data map[string]interface{}) []NetworkConnection {
	nt, ok := data["network_trace"].(map[string]interface{})
	if !ok {
		return nil
	}

	connectionsRaw, ok := nt["connections"].([]interface{})
	if !ok {
		return nil
	}

	var conns []NetworkConnection
	for _, raw := range connectionsRaw {
		connMap, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		conn := NetworkConnection{
			Protocol: strField(connMap, "protocol"),
		}

		if dest, ok := connMap["destination"].(map[string]interface{}); ok {
			conn.Hostname = strField(dest, "hostname")
			conn.IP = strField(dest, "ip")
		}

		if exchangesRaw, ok := connMap["http_exchanges"].([]interface{}); ok {
			for _, exRaw := range exchangesRaw {
				exMap, ok := exRaw.(map[string]interface{})
				if !ok {
					continue
				}
				ex := parseExchange(exMap)
				if ex.URL != "" {
					conn.Exchanges = append(conn.Exchanges, ex)
				}
			}
		}

		if conn.Hostname != "" {
			conns = append(conns, conn)
		}
	}

	return conns
}

func parseExchange(exMap map[string]interface{}) NetworkExchange {
	var ex NetworkExchange

	if req, ok := exMap["request"].(map[string]interface{}); ok {
		ex.URL = strField(req, "url")
		ex.Method = strField(req, "method")
		if hdrs, ok := req["headers"].(map[string]interface{}); ok {
			ex.Referer = firstHeader(hdrs, "Referer")
			ex.UserAgent = firstHeader(hdrs, "User-Agent")
		}
	}

	if resp, ok := exMap["response"].(map[string]interface{}); ok {
		if sc, ok := resp["status_code"].(float64); ok {
			ex.StatusCode = int(sc)
		}
		if body, ok := resp["body"].(map[string]interface{}); ok {
			ex.BodyHash = strField(body, "hash")
		}
	}

	return ex
}

// firstHeader returns a header's first value.
func firstHeader(hdrs map[string]interface{}, name string) string {
	if raw, ok := hdrs[name].([]interface{}); ok && len(raw) > 0 {
		if v, ok := raw[0].(string); ok {
			return v
		}
	}
	return ""
}

// isSuccessful returns true for 2xx responses or 0 (not captured).
func isSuccessful(statusCode int) bool {
	return statusCode == 0 || (statusCode >= 200 && statusCode < 300)
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
