package network

import (
	"testing"

	"github.com/sbomit/sbomit/pkg/attestation"
	"github.com/sbomit/sbomit/pkg/resolver"
)

// mockDomainResolver implements DomainResolver for testing.
type mockDomainResolver struct {
	domains  []string
	packages []resolver.PackageInfo
}

func (m *mockDomainResolver) Domains() []string {
	return m.domains
}

func (m *mockDomainResolver) Resolve(conn NetworkConnection) []resolver.PackageInfo {
	return m.packages
}

func TestExtractConnections(t *testing.T) {
	attestations := []attestation.TypedAttestation{
		{
			Type: "network-trace",
			Data: map[string]interface{}{
				"network_trace": map[string]interface{}{
					"connections": []interface{}{
						map[string]interface{}{
							"protocol": "tcp",
							"destination": map[string]interface{}{
								"hostname": "example.com",
								"ip":       "192.0.2.1",
							},
							"http_exchanges": []interface{}{
								map[string]interface{}{
									"request": map[string]interface{}{
										"url":    "https://example.com/pkg",
										"method": "GET",
										"headers": map[string]interface{}{
											"Referer": []interface{}{"https://ref.com"},
										},
									},
									"response": map[string]interface{}{
										"status_code": float64(200),
										"body": map[string]interface{}{
											"hash": "abcdef123456",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Type: "other-type",
			Data: map[string]interface{}{},
		},
	}

	conns := ExtractConnections(attestations)

	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	conn := conns[0]
	if conn.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", conn.Protocol)
	}
	if conn.Hostname != "example.com" {
		t.Errorf("expected hostname example.com, got %s", conn.Hostname)
	}
	if conn.IP != "192.0.2.1" {
		t.Errorf("expected IP 192.0.2.1, got %s", conn.IP)
	}
	if len(conn.Exchanges) != 1 {
		t.Fatalf("expected 1 exchange, got %d", len(conn.Exchanges))
	}

	ex := conn.Exchanges[0]
	if ex.URL != "https://example.com/pkg" {
		t.Errorf("expected URL, got %s", ex.URL)
	}
	if ex.Method != "GET" {
		t.Errorf("expected Method GET, got %s", ex.Method)
	}
	if ex.Referer != "https://ref.com" {
		t.Errorf("expected Referer, got %s", ex.Referer)
	}
	if ex.StatusCode != 200 {
		t.Errorf("expected StatusCode 200, got %d", ex.StatusCode)
	}
	if ex.BodyHash != "abcdef123456" {
		t.Errorf("expected BodyHash, got %s", ex.BodyHash)
	}
}

func TestResolveAllRoutingAndDeduplication(t *testing.T) {
	c := &Chain{byDomain: make(map[string]DomainResolver)}
	dr1 := &mockDomainResolver{
		domains: []string{"example.com"},
		packages: []resolver.PackageInfo{
			{Name: "pkgA", Version: "1.0", PURL: "pkg:generic/pkgA@1.0"},
			{Name: "pkgA", Version: "1.0", PURL: "pkg:generic/pkgA@1.0"}, // Dupe
			{Name: "pkgC", Version: "1.0", PURL: ""},                     // No PURL, should be skipped
		},
	}
	dr2 := &mockDomainResolver{
		domains: []string{"other.com"},
		packages: []resolver.PackageInfo{
			{Name: "pkgB", Version: "2.0", PURL: "pkg:generic/pkgB@2.0"},
		},
	}
	c.byDomain["example.com"] = dr1
	c.byDomain["other.com"] = dr2

	conns := []NetworkConnection{
		{Hostname: "example.com"},
		{Hostname: "other.com"},
		{Hostname: "unhandled.com"},
	}

	pkgs := c.ResolveAll(conns)

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages after deduplication, got %d", len(pkgs))
	}

	foundA := false
	foundB := false
	for _, p := range pkgs {
		if p.PURL == "pkg:generic/pkgA@1.0" {
			foundA = true
		} else if p.PURL == "pkg:generic/pkgB@2.0" {
			foundB = true
		}
	}

	if !foundA || !foundB {
		t.Errorf("expected both pkgA and pkgB to be resolved, got pkgs=%+v", pkgs)
	}
}