package network

import (
	"testing"

	"github.com/sbomit/sbomit/pkg/attestation"
)

// ---------------------------------------------------------------------------
// GoNetworkResolver
// ---------------------------------------------------------------------------

func TestGoNetworkResolver_ParsesDirectProxyURL(t *testing.T) {
	r := NewGoNetworkResolver()
	conn := NetworkConnection{
		Hostname: "proxy.golang.org",
		IP:       "1.2.3.4",
		Exchanges: []NetworkExchange{
			{URL: "https://proxy.golang.org/github.com/cilium/ebpf/@v/v0.20.0.zip", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:golang/github.com/cilium/ebpf@v0.20.0" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
	if pkgs[0].DownloadIP != "1.2.3.4" {
		t.Fatalf("expected download IP to be captured, got %q", pkgs[0].DownloadIP)
	}
}

func TestGoNetworkResolver_FallsBackToRefererForStorageGoogleapis(t *testing.T) {
	r := NewGoNetworkResolver()
	conn := NetworkConnection{
		Hostname: "storage.googleapis.com",
		IP:       "5.6.7.8",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://storage.googleapis.com/some/cdn/path",
				Referer:    "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip",
				StatusCode: 200,
			},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package via Referer fallback, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:golang/github.com/pkg/errors@v0.9.1" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestGoNetworkResolver_DeduplicatesWithinSingleConnection(t *testing.T) {
	r := NewGoNetworkResolver()
	conn := NetworkConnection{
		Hostname: "proxy.golang.org",
		Exchanges: []NetworkExchange{
			{URL: "https://proxy.golang.org/golang.org/x/net/@v/v0.33.0.mod", StatusCode: 200},
			{URL: "https://proxy.golang.org/golang.org/x/net/@v/v0.33.0.info", StatusCode: 200},
			{URL: "https://proxy.golang.org/golang.org/x/net/@v/v0.33.0.zip", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected dedup to produce 1 package, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:golang/golang.org/x/net@v0.33.0" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestGoNetworkResolver_SkipsFailedResponses(t *testing.T) {
	r := NewGoNetworkResolver()
	conn := NetworkConnection{
		Hostname: "proxy.golang.org",
		Exchanges: []NetworkExchange{
			{URL: "https://proxy.golang.org/github.com/foo/bar/@v/v1.0.0.zip", StatusCode: 404},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages for failed response, got %d", len(pkgs))
	}
}

func TestGoNetworkResolver_DecodesUppercaseEscaping(t *testing.T) {
	r := NewGoNetworkResolver()
	conn := NetworkConnection{
		Hostname: "proxy.golang.org",
		Exchanges: []NetworkExchange{
			{URL: "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.6.0.zip", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:golang/github.com/BurntSushi/toml@v1.6.0" {
		t.Fatalf("uppercase decoding failed, PURL: %s", pkgs[0].PURL)
	}
}

// ---------------------------------------------------------------------------
// PythonNetworkResolver
// ---------------------------------------------------------------------------

func TestPythonNetworkResolver_ParsesWheelFilename(t *testing.T) {
	r := NewPythonNetworkResolver()
	conn := NetworkConnection{
		Hostname: "files.pythonhosted.org",
		IP:       "9.10.11.12",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://files.pythonhosted.org/packages/abc/requests-2.31.0-py3-none-any.whl",
				StatusCode: 200,
			},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:pypi/requests@2.31.0" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestPythonNetworkResolver_ParsesSdistFilename(t *testing.T) {
	r := NewPythonNetworkResolver()
	conn := NetworkConnection{
		Hostname: "files.pythonhosted.org",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://files.pythonhosted.org/packages/abc/urllib3-2.0.7.tar.gz",
				StatusCode: 200,
			},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package for sdist, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:pypi/urllib3@2.0.7" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestPythonNetworkResolver_ParsesPyPIJsonAPI(t *testing.T) {
	r := NewPythonNetworkResolver()
	conn := NetworkConnection{
		Hostname: "pypi.org",
		Exchanges: []NetworkExchange{
			{URL: "https://pypi.org/pypi/certifi/2025.1.31/json", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package from JSON API, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:pypi/certifi@2025.1.31" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestPythonNetworkResolver_NormalizesPackageName(t *testing.T) {
	r := NewPythonNetworkResolver()
	conn := NetworkConnection{
		Hostname: "files.pythonhosted.org",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://files.pythonhosted.org/packages/abc/Pillow-10.0.0-cp311-cp311-manylinux.whl",
				StatusCode: 200,
			},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "pillow" {
		t.Fatalf("expected normalized name 'pillow', got %q", pkgs[0].Name)
	}
}

// ---------------------------------------------------------------------------
// RustNetworkResolver
// ---------------------------------------------------------------------------

func TestRustNetworkResolver_ParsesCrateStaticPath(t *testing.T) {
	r := NewRustNetworkResolver()
	conn := NetworkConnection{
		Hostname: "static.crates.io",
		IP:       "13.14.15.16",
		Exchanges: []NetworkExchange{
			{URL: "https://static.crates.io/crates/serde/serde-1.0.193.crate", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:cargo/serde@1.0.193" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestRustNetworkResolver_ParsesCratesIOApiDownloadEndpoint(t *testing.T) {
	r := NewRustNetworkResolver()
	conn := NetworkConnection{
		Hostname: "crates.io",
		Exchanges: []NetworkExchange{
			{URL: "https://crates.io/api/v1/crates/tokio/1.36.0/download", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package from API endpoint, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:cargo/tokio@1.36.0" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestRustNetworkResolver_SkipsNonDownloadPaths(t *testing.T) {
	r := NewRustNetworkResolver()
	conn := NetworkConnection{
		Hostname: "crates.io",
		Exchanges: []NetworkExchange{
			{URL: "https://crates.io/api/v1/crates?q=serde", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages for non-download path, got %d", len(pkgs))
	}
}

// ---------------------------------------------------------------------------
// JavaScriptNetworkResolver
// ---------------------------------------------------------------------------

func TestJavaScriptNetworkResolver_ParsesScopedPackageTarball(t *testing.T) {
	r := NewJavaScriptNetworkResolver()
	conn := NetworkConnection{
		Hostname: "registry.npmjs.org",
		IP:       "17.18.19.20",
		Exchanges: []NetworkExchange{
			{URL: "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Ecosystem != "npm" {
		t.Fatalf("expected ecosystem npm, got %q", pkgs[0].Ecosystem)
	}
	if pkgs[0].Version != "7.24.0" {
		t.Fatalf("expected version 7.24.0, got %q", pkgs[0].Version)
	}
}

func TestJavaScriptNetworkResolver_ParsesUnscopedPackageTarball(t *testing.T) {
	r := NewJavaScriptNetworkResolver()
	conn := NetworkConnection{
		Hostname: "registry.npmjs.org",
		Exchanges: []NetworkExchange{
			{URL: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", StatusCode: 200},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("unexpected PURL: %s", pkgs[0].PURL)
	}
}

func TestJavaScriptNetworkResolver_SkipsFailedResponses(t *testing.T) {
	r := NewJavaScriptNetworkResolver()
	conn := NetworkConnection{
		Hostname: "registry.npmjs.org",
		Exchanges: []NetworkExchange{
			{URL: "https://registry.npmjs.org/express/-/express-5.0.0.tgz", StatusCode: 503},
		},
	}
	pkgs := r.Resolve(conn)
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages for failed HTTP response, got %d", len(pkgs))
	}
}

// ---------------------------------------------------------------------------
// Chain (routing + global dedup)
// ---------------------------------------------------------------------------

func TestChain_RoutesConnectionsByHostname(t *testing.T) {
	chain := NewChain()
	conns := []NetworkConnection{
		{
			Hostname: "proxy.golang.org",
			Exchanges: []NetworkExchange{
				{URL: "https://proxy.golang.org/github.com/spf13/cobra/@v/v1.8.0.zip", StatusCode: 200},
			},
		},
		{
			Hostname: "files.pythonhosted.org",
			Exchanges: []NetworkExchange{
				{URL: "https://files.pythonhosted.org/packages/abc/boto3-1.34.0-py3-none-any.whl", StatusCode: 200},
			},
		},
		{
			Hostname: "registry.npmjs.org",
			Exchanges: []NetworkExchange{
				{URL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz", StatusCode: 200},
			},
		},
		{
			Hostname: "static.crates.io",
			Exchanges: []NetworkExchange{
				{URL: "https://static.crates.io/crates/rand/rand-0.8.5.crate", StatusCode: 200},
			},
		},
	}
	pkgs := chain.ResolveAll(conns)
	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages (one per ecosystem), got %d", len(pkgs))
	}
	ecosystems := make(map[string]struct{})
	for _, p := range pkgs {
		ecosystems[p.Ecosystem] = struct{}{}
	}
	for _, eco := range []string{"golang", "pypi", "npm", "cargo"} {
		if _, ok := ecosystems[eco]; !ok {
			t.Errorf("missing ecosystem: %s", eco)
		}
	}
}

func TestChain_DeduplicatesIdenticalPURLsAcrossConnections(t *testing.T) {
	chain := NewChain()
	conns := []NetworkConnection{
		{
			Hostname: "proxy.golang.org",
			Exchanges: []NetworkExchange{
				{URL: "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip", StatusCode: 200},
			},
		},
		{
			Hostname: "proxy.golang.org",
			Exchanges: []NetworkExchange{
				{URL: "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.mod", StatusCode: 200},
			},
		},
	}
	pkgs := chain.ResolveAll(conns)
	if len(pkgs) != 1 {
		t.Fatalf("expected dedup to produce 1 package, got %d", len(pkgs))
	}
}

func TestChain_IgnoresUnknownHostnames(t *testing.T) {
	chain := NewChain()
	conns := []NetworkConnection{
		{
			Hostname: "some-random-cdn.example.com",
			Exchanges: []NetworkExchange{
				{URL: "https://some-random-cdn.example.com/packages/something.tar.gz", StatusCode: 200},
			},
		},
	}
	pkgs := chain.ResolveAll(conns)
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages for unknown hostname, got %d", len(pkgs))
	}
}

// ---------------------------------------------------------------------------
// ExtractConnections (network-trace attestation parsing)
// ---------------------------------------------------------------------------

func TestExtractConnections_ParsesNetworkTraceAttestation(t *testing.T) {
	attestations := []attestation.TypedAttestation{
		{
			Type: "network-trace",
			Data: map[string]interface{}{
				"network_trace": map[string]interface{}{
					"connections": []interface{}{
						map[string]interface{}{
							"protocol": "tcp",
							"destination": map[string]interface{}{
								"hostname": "proxy.golang.org",
								"ip":       "142.250.80.113",
							},
							"http_exchanges": []interface{}{
								map[string]interface{}{
									"request": map[string]interface{}{
										"url":    "https://proxy.golang.org/github.com/gorilla/mux/@v/v1.8.1.zip",
										"method": "GET",
									},
									"response": map[string]interface{}{
										"status_code": float64(200),
									},
								},
							},
						},
					},
				},
			},
		},
	}
	conns := ExtractConnections(attestations)
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	if conns[0].Hostname != "proxy.golang.org" {
		t.Fatalf("expected hostname proxy.golang.org, got %q", conns[0].Hostname)
	}
	if conns[0].IP != "142.250.80.113" {
		t.Fatalf("expected IP to be captured, got %q", conns[0].IP)
	}
	if len(conns[0].Exchanges) != 1 {
		t.Fatalf("expected 1 exchange, got %d", len(conns[0].Exchanges))
	}
	if conns[0].Exchanges[0].StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", conns[0].Exchanges[0].StatusCode)
	}
}

func TestExtractConnections_IgnoresNonNetworkTraceAttestations(t *testing.T) {
	attestations := []attestation.TypedAttestation{
		{Type: "material", Data: map[string]interface{}{}},
		{Type: "command-run", Data: map[string]interface{}{}},
	}
	conns := ExtractConnections(attestations)
	if len(conns) != 0 {
		t.Fatalf("expected 0 connections for non-network-trace attestations, got %d", len(conns))
	}
}

func TestExtractConnections_SkipsConnectionsWithoutHostname(t *testing.T) {
	attestations := []attestation.TypedAttestation{
		{
			Type: "network-trace",
			Data: map[string]interface{}{
				"network_trace": map[string]interface{}{
					"connections": []interface{}{
						map[string]interface{}{
							"protocol": "tcp",
						},
					},
				},
			},
		},
	}
	conns := ExtractConnections(attestations)
	if len(conns) != 0 {
		t.Fatalf("expected 0 connections (no hostname), got %d", len(conns))
	}
}

func TestExtractConnections_ParsesRefererHeader(t *testing.T) {
	attestations := []attestation.TypedAttestation{
		{
			Type: "network-trace",
			Data: map[string]interface{}{
				"network_trace": map[string]interface{}{
					"connections": []interface{}{
						map[string]interface{}{
							"destination": map[string]interface{}{
								"hostname": "storage.googleapis.com",
								"ip":       "1.2.3.4",
							},
							"http_exchanges": []interface{}{
								map[string]interface{}{
									"request": map[string]interface{}{
										"url":    "https://storage.googleapis.com/some/cdn",
										"method": "GET",
										"headers": map[string]interface{}{
											"Referer": []interface{}{
												"https://proxy.golang.org/github.com/spf13/pflag/@v/v1.0.5.zip",
											},
										},
									},
									"response": map[string]interface{}{
										"status_code": float64(200),
									},
								},
							},
						},
					},
				},
			},
		},
	}
	conns := ExtractConnections(attestations)
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	if conns[0].Exchanges[0].Referer != "https://proxy.golang.org/github.com/spf13/pflag/@v/v1.0.5.zip" {
		t.Fatalf("Referer not captured correctly: %q", conns[0].Exchanges[0].Referer)
	}
}
