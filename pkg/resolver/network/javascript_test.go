package network

import (
	"testing"
)

func TestJavaScriptNetworkResolver(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		statusCode   int
		bodyHash     string
		expectPkg    bool
		expectedName string
		expectedVer  string
		expectedHash string
	}{
		{
			name:         "non-scoped tarball",
			url:          "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "lodash",
			expectedVer:  "4.17.21",
		},
		{
			name:         "scoped tarball",
			url:          "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "@babel/core",
			expectedVer:  "7.24.0",
		},
		{
			name:         "non-scoped metadata endpoint",
			url:          "https://registry.npmjs.org/express/4.18.2",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "express",
			expectedVer:  "4.18.2",
		},
		{
			name:         "scoped metadata endpoint",
			url:          "https://registry.npmjs.org/@types/node/18.0.0",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "@types/node",
			expectedVer:  "18.0.0",
		},
		{
			name:         "pre-release version in tarball",
			url:          "https://registry.npmjs.org/express/-/express-5.0.0-beta.1.tgz",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "express",
			expectedVer:  "5.0.0-beta.1",
		},
		{
			name:         "normalizes package name to lowercase",
			url:          "https://registry.npmjs.org/@MyOrg/Pkg/-/Pkg-1.0.0.tgz",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "@myorg/pkg",
			expectedVer:  "1.0.0",
		},
		{
			name:       "skips 404 status",
			url:        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			statusCode: 404,
			expectPkg:  false,
		},
		{
			name:       "non-matching path produces no package",
			url:        "https://registry.npmjs.org/-/npm/v1/security/audits",
			statusCode: 200,
			expectPkg:  false,
		},
		{
			name:         "records body hash as sha256",
			url:          "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			statusCode:   200,
			bodyHash:     "cafebabe",
			expectPkg:    true,
			expectedName: "lodash",
			expectedVer:  "4.17.21",
			expectedHash: "cafebabe",
		},
	}

	resolver := NewJavaScriptNetworkResolver()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := NetworkConnection{
				Hostname: "registry.npmjs.org",
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

func TestJavaScriptNetworkResolver_Deduplication(t *testing.T) {
	resolver := NewJavaScriptNetworkResolver()
	conn := NetworkConnection{
		Hostname: "registry.npmjs.org",
		Exchanges: []NetworkExchange{
			{URL: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", StatusCode: 200},
			{URL: "https://registry.npmjs.org/lodash/4.17.21", StatusCode: 200},
		},
	}

	pkgs := resolver.Resolve(conn)
	if len(pkgs) != 1 {
		t.Errorf("expected 1 package after dedup of tgz+metadata, got %d", len(pkgs))
	}
}
