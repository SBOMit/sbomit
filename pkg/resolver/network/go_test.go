package network

import (
	"testing"
)

func TestGoNetworkResolver(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		url          string
		referer      string
		statusCode   int
		bodyHash     string
		expectPkg    bool
		expectedName string
		expectedVer  string
		expectedHash string
	}{
		{
			name:         "resolves zip from proxy.golang.org",
			hostname:     "proxy.golang.org",
			url:          "https://proxy.golang.org/github.com/cilium/ebpf/@v/v0.20.0.zip",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "github.com/cilium/ebpf",
			expectedVer:  "v0.20.0",
		},
		{
			name:         "resolves mod file",
			hostname:     "proxy.golang.org",
			url:          "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.mod",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "github.com/pkg/errors",
			expectedVer:  "v0.9.1",
		},
		{
			name:         "resolves info file",
			hostname:     "proxy.golang.org",
			url:          "https://proxy.golang.org/golang.org/x/net/@v/v0.21.0.info",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "golang.org/x/net",
			expectedVer:  "v0.21.0",
		},
		{
			name:         "decodes uppercase-encoded module path",
			hostname:     "proxy.golang.org",
			url:          "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.3.2.zip",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "github.com/BurntSushi/toml",
			expectedVer:  "v1.3.2",
		},
		{
			name:         "resolves from storage.googleapis.com via proxy Referer",
			hostname:     "storage.googleapis.com",
			url:          "https://storage.googleapis.com/gomodules/abc123",
			referer:      "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "github.com/pkg/errors",
			expectedVer:  "v0.9.1",
		},
		{
			name:       "storage.googleapis.com without proxy Referer produces no package",
			hostname:   "storage.googleapis.com",
			url:        "https://storage.googleapis.com/gomodules/abc123",
			referer:    "https://other.cdn.com/path",
			statusCode: 200,
			expectPkg:  false,
		},
		{
			name:       "skips 404 status",
			hostname:   "proxy.golang.org",
			url:        "https://proxy.golang.org/github.com/cilium/ebpf/@v/v0.20.0.zip",
			statusCode: 404,
			expectPkg:  false,
		},
		{
			name:         "zero status treated as success",
			hostname:     "proxy.golang.org",
			url:          "https://proxy.golang.org/github.com/cilium/ebpf/@v/v0.20.0.zip",
			statusCode:   0,
			expectPkg:    true,
			expectedName: "github.com/cilium/ebpf",
			expectedVer:  "v0.20.0",
		},
		{
			name:       "non-matching path produces no package",
			hostname:   "proxy.golang.org",
			url:        "https://proxy.golang.org/sumdb/lookup/github.com/cilium/ebpf@v0.20.0",
			statusCode: 200,
			expectPkg:  false,
		},
		{
			name:         "records body hash as sha256",
			hostname:     "proxy.golang.org",
			url:          "https://proxy.golang.org/github.com/cilium/ebpf/@v/v0.20.0.zip",
			statusCode:   200,
			bodyHash:     "deadbeef",
			expectPkg:    true,
			expectedName: "github.com/cilium/ebpf",
			expectedVer:  "v0.20.0",
			expectedHash: "deadbeef",
		},
	}

	resolver := NewGoNetworkResolver()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := NetworkConnection{
				Hostname: tc.hostname,
				Exchanges: []NetworkExchange{
					{
						URL:        tc.url,
						Referer:    tc.referer,
						StatusCode: tc.statusCode,
						BodyHash:   tc.bodyHash,
					},
				},
			}

			pkgs := resolver.Resolve(conn)

			if !tc.expectPkg {
				if len(pkgs) != 0 {
					t.Errorf("expected no packages, got %d", len(pkgs))
				}
				return
			}

			if len(pkgs) != 1 {
				t.Fatalf("expected 1 package, got %d", len(pkgs))
			}
			pkg := pkgs[0]
			if pkg.Name != tc.expectedName {
				t.Errorf("name = %q, want %q", pkg.Name, tc.expectedName)
			}
			if pkg.Version != tc.expectedVer {
				t.Errorf("version = %q, want %q", pkg.Version, tc.expectedVer)
			}
			if tc.expectedHash != "" && pkg.Hashes["sha256"] != tc.expectedHash {
				t.Errorf("hash = %q, want %q", pkg.Hashes["sha256"], tc.expectedHash)
			}
		})
	}
}

func TestGoNetworkResolver_Deduplication(t *testing.T) {
	resolver := NewGoNetworkResolver()
	conn := NetworkConnection{
		Hostname: "proxy.golang.org",
		Exchanges: []NetworkExchange{
			{URL: "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip", StatusCode: 200},
			{URL: "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.mod", StatusCode: 200},
		},
	}

	pkgs := resolver.Resolve(conn)
	if len(pkgs) != 1 {
		t.Errorf("expected 1 package after dedup of zip+mod, got %d", len(pkgs))
	}
}
