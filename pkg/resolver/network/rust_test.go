package network

import (
	"testing"
)

func TestRustNetworkResolver(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		url          string
		statusCode   int
		bodyHash     string
		expectPkg    bool
		expectedName string
		expectedVer  string
		expectedHash string
	}{
		{
			name:         "resolves crate file from static.crates.io",
			hostname:     "static.crates.io",
			url:          "https://static.crates.io/crates/serde/serde-1.0.200.crate",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "serde",
			expectedVer:  "1.0.200",
		},
		{
			name:         "resolves via API download endpoint",
			hostname:     "crates.io",
			url:          "https://crates.io/api/v1/crates/tokio/1.38.0/download",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "tokio",
			expectedVer:  "1.38.0",
		},
		{
			name:         "hyphenated crate name",
			hostname:     "static.crates.io",
			url:          "https://static.crates.io/crates/serde-derive/serde-derive-1.0.200.crate",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "serde-derive",
			expectedVer:  "1.0.200",
		},
		{
			name:         "underscore crate name",
			hostname:     "static.crates.io",
			url:          "https://static.crates.io/crates/serde_json/serde_json-1.0.117.crate",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "serde_json",
			expectedVer:  "1.0.117",
		},
		{
			name:         "pre-release version in crate file",
			hostname:     "static.crates.io",
			url:          "https://static.crates.io/crates/tokio/tokio-1.38.0-beta.1.crate",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "tokio",
			expectedVer:  "1.38.0-beta.1",
		},
		{
			name:         "pre-release version via API endpoint",
			hostname:     "crates.io",
			url:          "https://crates.io/api/v1/crates/tokio/1.38.0-beta.1/download",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "tokio",
			expectedVer:  "1.38.0-beta.1",
		},
		{
			name:       "skips 404 status",
			hostname:   "static.crates.io",
			url:        "https://static.crates.io/crates/serde/serde-1.0.200.crate",
			statusCode: 404,
			expectPkg:  false,
		},
		{
			name:       "non-matching path produces no package",
			hostname:   "index.crates.io",
			url:        "https://index.crates.io/se/rd/serde",
			statusCode: 200,
			expectPkg:  false,
		},
		{
			name:         "records body hash as sha256",
			hostname:     "static.crates.io",
			url:          "https://static.crates.io/crates/serde/serde-1.0.200.crate",
			statusCode:   200,
			bodyHash:     "f00dcafe",
			expectPkg:    true,
			expectedName: "serde",
			expectedVer:  "1.0.200",
			expectedHash: "f00dcafe",
		},
	}

	resolver := NewRustNetworkResolver()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := NetworkConnection{
				Hostname: tc.hostname,
				Exchanges: []NetworkExchange{
					{
						URL:        tc.url,
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

func TestRustNetworkResolver_Deduplication(t *testing.T) {
	resolver := NewRustNetworkResolver()
	conn := NetworkConnection{
		Hostname: "static.crates.io",
		Exchanges: []NetworkExchange{
			{URL: "https://static.crates.io/crates/tokio/tokio-1.38.0.crate", StatusCode: 200},
			{URL: "https://crates.io/api/v1/crates/tokio/1.38.0/download", StatusCode: 200},
		},
	}

	pkgs := resolver.Resolve(conn)
	if len(pkgs) != 1 {
		t.Errorf("expected 1 package after dedup of crate file+API, got %d", len(pkgs))
	}
}
