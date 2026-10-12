package network

import (
	"testing"

	"github.com/sbomit/sbomit/pkg/attestation"
)

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
								"hostname": "proxy.golang.org",
								"ip":       "142.250.190.49",
							},
							"http_exchanges": []interface{}{
								map[string]interface{}{
									"request": map[string]interface{}{
										"url":    "https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.zip",
										"method": "GET",
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
			Type: "material",
			Data: map[string]interface{}{},
		},
	}

	conns := ExtractConnections(attestations)
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection extracted, got %d", len(conns))
	}

	conn := conns[0]
	if conn.Hostname != "proxy.golang.org" || conn.IP != "142.250.190.49" || conn.Protocol != "tcp" {
		t.Errorf("unexpected connection metadata: %+v", conn)
	}

	if len(conn.Exchanges) != 1 {
		t.Fatalf("expected 1 http exchange, got %d", len(conn.Exchanges))
	}
	ex := conn.Exchanges[0]
	if ex.URL != "https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.zip" || ex.StatusCode != 200 || ex.BodyHash != "abcdef123456" {
		t.Errorf("unexpected exchange details: %+v", ex)
	}
}

func TestNetworkChainResolveAll(t *testing.T) {
	chain := NewChain()

	conns := []NetworkConnection{
		{
			Hostname: "proxy.golang.org",
			IP:       "142.250.190.49",
			Exchanges: []NetworkExchange{
				{
					URL:        "https://proxy.golang.org/github.com/spf13/cobra/@v/v1.8.0.zip",
					StatusCode: 200,
					BodyHash:   "hash-cobra",
				},
				{
					URL:        "https://proxy.golang.org/github.com/spf13/cobra/@v/v1.8.0.mod",
					StatusCode: 200,
				},
			},
		},
		{
			Hostname: "files.pythonhosted.org",
			IP:       "151.101.128.223",
			Exchanges: []NetworkExchange{
				{
					URL:        "https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl",
					StatusCode: 200,
					BodyHash:   "hash-requests",
				},
				// Error status code should be ignored
				{
					URL:        "https://files.pythonhosted.org/packages/failed-1.0.0.tar.gz",
					StatusCode: 404,
				},
			},
		},
		{
			Hostname: "registry.npmjs.org",
			IP:       "104.16.0.0",
			Exchanges: []NetworkExchange{
				{
					URL:        "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
					StatusCode: 200,
					BodyHash:   "hash-babel",
				},
			},
		},
		{
			Hostname: "static.crates.io",
			IP:       "13.35.14.39",
			Exchanges: []NetworkExchange{
				{
					URL:        "https://static.crates.io/crates/serde/serde-1.0.197.crate",
					StatusCode: 200,
					BodyHash:   "hash-serde",
				},
			},
		},
		// Unknown hostname should be safely ignored
		{
			Hostname: "unknown.domain.org",
			Exchanges: []NetworkExchange{
				{URL: "https://unknown.domain.org/something", StatusCode: 200},
			},
		},
	}

	packages := chain.ResolveAll(conns)

	if len(packages) != 4 {
		t.Fatalf("expected 4 resolved packages across ecosystems, got %d", len(packages))
	}

	pkgsByPURL := make(map[string]bool)
	for _, p := range packages {
		pkgsByPURL[p.PURL] = true
	}

	expected := []string{
		"pkg:golang/github.com/spf13/cobra@v1.8.0",
		"pkg:pypi/requests@2.31.0",
		"pkg:npm/@babel/core@7.24.0",
		"pkg:cargo/serde@1.0.197",
	}

	for _, exp := range expected {
		if !pkgsByPURL[exp] {
			t.Errorf("expected package %q in resolved network packages", exp)
		}
	}
}

func TestGoNetworkResolverStorageGoogleapisReferer(t *testing.T) {
	r := NewGoNetworkResolver()

	conn := NetworkConnection{
		Hostname: "storage.googleapis.com",
		IP:       "142.250.190.128",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://storage.googleapis.com/golang-pkg-mod/abc12345",
				Referer:    "https://proxy.golang.org/github.com/cilium/ebpf/@v/v0.12.0.zip",
				StatusCode: 200,
				BodyHash:   "ebpf-hash",
			},
		},
	}

	pkgs := r.Resolve(conn)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package resolved from referer, got %d", len(pkgs))
	}

	pkg := pkgs[0]
	if pkg.PURL != "pkg:golang/github.com/cilium/ebpf@v0.12.0" {
		t.Errorf("unexpected purl: %s", pkg.PURL)
	}
	if pkg.DownloadURL != "https://proxy.golang.org/github.com/cilium/ebpf/@v/v0.12.0.zip" {
		t.Errorf("expected canonical proxy URL preserved in DownloadURL, got %s", pkg.DownloadURL)
	}
}

func TestPythonNetworkResolverAPIAndTarGz(t *testing.T) {
	r := NewPythonNetworkResolver()

	conn := NetworkConnection{
		Hostname: "pypi.org",
		IP:       "151.101.128.223",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://pypi.org/pypi/certifi/2023.7.22/json",
				StatusCode: 200,
			},
			{
				URL:        "https://files.pythonhosted.org/packages/source/f/flask/flask-3.0.0.tar.gz",
				StatusCode: 200,
				BodyHash:   "flask-hash",
			},
		},
	}

	pkgs := r.Resolve(conn)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	pkgsByPURL := make(map[string]bool)
	for _, p := range pkgs {
		pkgsByPURL[p.PURL] = true
	}

	if !pkgsByPURL["pkg:pypi/certifi@2023.7.22"] {
		t.Errorf("expected certifi package resolved")
	}
	if !pkgsByPURL["pkg:pypi/flask@3.0.0"] {
		t.Errorf("expected flask package resolved")
	}
}
