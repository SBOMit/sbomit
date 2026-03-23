// Package network resolves packages from network-trace witness attestations.
// Each ecosystem registers the hostnames it owns and a URL parsing strategy.
// The Chain routes connections by hostname to the right DomainResolver.
package network

import (
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
	StatusCode int
	BodyHash   string
}

// DomainResolver resolves packages for a fixed set of hostnames.
// Each ecosystem file registers its own DomainResolver with the Chain.
type DomainResolver interface {
	// Domains returns the hostnames this resolver handles.
	Domains() []string
	// Resolve extracts recognized packages from all exchanges in the connection.
	Resolve(conn NetworkConnection) []resolver.PackageInfo
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
	} {
		for _, d := range r.Domains() {
			c.byDomain[d] = r
		}
	}
	return c
}

// ResolveAll resolves all connections, deduplicating by PURL.
func (c *Chain) ResolveAll(conns []NetworkConnection) []resolver.PackageInfo {
	seen := make(map[string]struct{})
	var packages []resolver.PackageInfo
	for _, conn := range conns {
		dr, ok := c.byDomain[conn.Hostname]
		if !ok {
			continue
		}
		for _, pkg := range dr.Resolve(conn) {
			if pkg.PURL == "" {
				continue
			}
			if _, already := seen[pkg.PURL]; already {
				continue
			}
			seen[pkg.PURL] = struct{}{}
			packages = append(packages, pkg)
		}
	}
	return packages
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
			// Referer header is an array of strings in the witness format
			if refRaw, ok := hdrs["Referer"].([]interface{}); ok && len(refRaw) > 0 {
				if refStr, ok := refRaw[0].(string); ok {
					ex.Referer = refStr
				}
			}
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
