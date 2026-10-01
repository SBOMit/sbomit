package network

import (
	"testing"
)

func TestJavaScriptNetworkResolverDomains(t *testing.T) {
	r := NewJavaScriptNetworkResolver()
	domains := r.Domains()
	if len(domains) != 2 {
		t.Fatalf("Expected 2 domains, got %d", len(domains))
	}
	if domains[0] != "registry.npmjs.org" && domains[1] != "registry.npmjs.org" {
		t.Errorf("Expected registry.npmjs.org to be in domains")
	}
}

func TestJavaScriptNetworkResolverResolve(t *testing.T) {
	r := NewJavaScriptNetworkResolver()

	conn := NetworkConnection{
		Hostname: "registry.npmjs.org",
		IP:       "104.16.0.0",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				StatusCode: 200,
				BodyHash:   "hash123",
			},
			{
				URL:        "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
				StatusCode: 200,
			},
			{
				URL:        "https://registry.npmjs.org/express/4.18.2", // meta endpoint
				StatusCode: 200,
			},
			{
				URL:        "https://registry.npmjs.org/notfound/-/notfound-1.0.0.tgz",
				StatusCode: 404,
			},
		},
	}

	pkgs := r.Resolve(conn)

	if len(pkgs) != 3 {
		t.Fatalf("Expected 3 packages, got %d", len(pkgs))
	}

	foundLodash := false
	foundBabel := false
	foundExpress := false

	for _, p := range pkgs {
		if p.Name == "lodash" {
			foundLodash = true
			if p.Version != "4.17.21" {
				t.Errorf("Expected lodash version 4.17.21, got %s", p.Version)
			}
			if p.Hashes["sha256"] != "hash123" {
				t.Errorf("Expected lodash hash hash123, got %s", p.Hashes["sha256"])
			}
		}
		if p.Name == "@babel/core" {
			foundBabel = true
			if p.Version != "7.24.0" {
				t.Errorf("Expected @babel/core version 7.24.0, got %s", p.Version)
			}
		}
		if p.Name == "express" {
			foundExpress = true
			if p.Version != "4.18.2" {
				t.Errorf("Expected express version 4.18.2, got %s", p.Version)
			}
		}
	}

	if !foundLodash || !foundBabel || !foundExpress {
		t.Errorf("Did not find all expected packages")
	}
}

func TestJSParseURL(t *testing.T) {
	r := NewJavaScriptNetworkResolver()

	tests := []struct {
		url     string
		name    string
		version string
		ok      bool
	}{
		{"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "lodash", "4.17.21", true},
		{"https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz", "@babel/core", "7.24.0", true},
		{"https://registry.npmjs.org/express/4.18.2", "express", "4.18.2", true},
		{"https://registry.npmjs.org/@types/node/14.0.0", "@types/node", "14.0.0", true},
		{"https://registry.npmjs.org/invalid-url", "", "", false},
		{"invalid-url-\x00", "", "", false},
	}

	for _, tc := range tests {
		n, v, ok := r.parseURL(tc.url)
		if ok != tc.ok {
			t.Errorf("Expected ok=%v for %s, got %v", tc.ok, tc.url, ok)
			continue
		}
		if ok {
			if n != tc.name {
				t.Errorf("Expected name %s, got %s", tc.name, n)
			}
			if v != tc.version {
				t.Errorf("Expected version %s, got %s", tc.version, v)
			}
		}
	}
}
