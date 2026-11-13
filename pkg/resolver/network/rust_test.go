package network

import (
	"testing"
)

func TestRustNetworkResolverDomains(t *testing.T) {
	r := NewRustNetworkResolver()
	domains := r.Domains()
	if len(domains) != 3 {
		t.Fatalf("Expected 3 domains, got %d", len(domains))
	}

	foundCrates := false
	foundStatic := false
	foundIndex := false

	for _, d := range domains {
		switch d {
		case "crates.io":
			foundCrates = true
		case "static.crates.io":
			foundStatic = true
		case "index.crates.io":
			foundIndex = true
		}
	}

	if !foundCrates || !foundStatic || !foundIndex {
		t.Errorf("Did not find all expected rust network domains")
	}
}

func TestRustNetworkResolverResolve(t *testing.T) {
	r := NewRustNetworkResolver()

	conn := NetworkConnection{
		Hostname: "crates.io",
		IP:       "13.35.14.39",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://crates.io/api/v1/crates/serde/1.0.136/download",
				StatusCode: 200,
				BodyHash:   "abcdef",
			},
			{
				URL:        "https://static.crates.io/crates/tokio/tokio-1.12.0.crate",
				StatusCode: 200,
			},
			{
				URL:        "https://crates.io/api/v1/crates/notfound/1.0.0/download",
				StatusCode: 404,
			},
		},
	}

	pkgs := r.Resolve(conn)

	if len(pkgs) != 2 {
		t.Fatalf("Expected 2 packages, got %d", len(pkgs))
	}

	foundSerde := false
	foundTokio := false

	for _, p := range pkgs {
		if p.Name == "serde" {
			foundSerde = true
			if p.Version != "1.0.136" {
				t.Errorf("Expected serde version 1.0.136, got %s", p.Version)
			}
			if p.Hashes["sha256"] != "abcdef" {
				t.Errorf("Expected serde hash abcdef, got %s", p.Hashes["sha256"])
			}
		}
		if p.Name == "tokio" {
			foundTokio = true
			if p.Version != "1.12.0" {
				t.Errorf("Expected tokio version 1.12.0, got %s", p.Version)
			}
		}
	}

	if !foundSerde || !foundTokio {
		t.Errorf("Did not find all expected packages")
	}
}

func TestRustParseURL(t *testing.T) {
	r := NewRustNetworkResolver()

	tests := []struct {
		url     string
		name    string
		version string
		ok      bool
	}{
		{"https://crates.io/api/v1/crates/serde/1.0.136/download", "serde", "1.0.136", true},
		{"https://static.crates.io/crates/tokio/tokio-1.12.0.crate", "tokio", "1.12.0", true},
		{"https://static.crates.io/crates/Rand-Core/Rand-Core-0.6.3.crate", "Rand-Core", "0.6.3", true},
		{"https://crates.io/api/v1/crates/serde/1.0.136/dependencies", "", "", false},
		{"https://crates.io/api/v1/crates/invalid/path", "", "", false},
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
