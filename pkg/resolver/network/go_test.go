package network

import (
	"testing"
)

func TestGoNetworkResolverDomains(t *testing.T) {
	r := NewGoNetworkResolver()
	domains := r.Domains()
	
	if len(domains) != 2 {
		t.Fatalf("Expected 2 domains, got %d", len(domains))
	}
	
	if domains[0] != "proxy.golang.org" && domains[1] != "proxy.golang.org" {
		t.Errorf("Expected proxy.golang.org to be in domains")
	}
	if domains[0] != "storage.googleapis.com" && domains[1] != "storage.googleapis.com" {
		t.Errorf("Expected storage.googleapis.com to be in domains")
	}
}

func TestGoNetworkResolverResolve(t *testing.T) {
	r := NewGoNetworkResolver()

	conn := NetworkConnection{
		Hostname: "proxy.golang.org",
		IP:       "1.2.3.4",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://proxy.golang.org/github.com/google/uuid/@v/v1.3.0.zip",
				StatusCode: 200,
				BodyHash:   "abcdef",
			},
			{
				URL:        "https://proxy.golang.org/github.com/sirupsen/logrus/@v/v1.9.0.info",
				StatusCode: 200,
			},
			{
				URL:        "https://proxy.golang.org/github.com/notfound/pkg/@v/v1.0.0.mod",
				StatusCode: 404, // Should be ignored
			},
		},
	}

	pkgs := r.Resolve(conn)

	if len(pkgs) != 2 {
		t.Fatalf("Expected 2 packages, got %d", len(pkgs))
	}

	foundUUID := false
	for _, p := range pkgs {
		if p.Name == "github.com/google/uuid" {
			foundUUID = true
			if p.Version != "v1.3.0" {
				t.Errorf("Expected uuid version v1.3.0, got %s", p.Version)
			}
			if p.Hashes["sha256"] != "abcdef" {
				t.Errorf("Expected sha256 abcdef, got %s", p.Hashes["sha256"])
			}
			if p.PURL != "pkg:golang/github.com/google/uuid@v1.3.0" {
				t.Errorf("Expected PURL pkg:golang/github.com/google/uuid@v1.3.0, got %s", p.PURL)
			}
		}
	}

	if !foundUUID {
		t.Errorf("Failed to find github.com/google/uuid")
	}
}

func TestGoNetworkResolverStorageGoogleapisRedirect(t *testing.T) {
	r := NewGoNetworkResolver()

	conn := NetworkConnection{
		Hostname: "storage.googleapis.com",
		IP:       "8.8.8.8",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://storage.googleapis.com/golang-proxy/something.zip",
				Referer:    "https://proxy.golang.org/golang.org/x/sys/@v/v0.1.0.zip",
				StatusCode: 200,
			},
			{
				URL:        "https://storage.googleapis.com/golang-proxy/other.zip",
				Referer:    "https://example.com/not-proxy",
				StatusCode: 200, // Should be ignored because referer doesn't match proxy.golang.org
			},
		},
	}

	pkgs := r.Resolve(conn)

	if len(pkgs) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(pkgs))
	}

	if pkgs[0].Name != "golang.org/x/sys" {
		t.Errorf("Expected golang.org/x/sys, got %s", pkgs[0].Name)
	}
	if pkgs[0].Version != "v0.1.0" {
		t.Errorf("Expected version v0.1.0, got %s", pkgs[0].Version)
	}
	if pkgs[0].DownloadURL != "https://proxy.golang.org/golang.org/x/sys/@v/v0.1.0.zip" {
		t.Errorf("Expected original proxy URL as DownloadURL, got %s", pkgs[0].DownloadURL)
	}
}

func TestParseProxyURL(t *testing.T) {
	r := NewGoNetworkResolver()

	tests := []struct {
		url     string
		module  string
		version string
		ok      bool
	}{
		{"https://proxy.golang.org/github.com/google/uuid/@v/v1.3.0.zip", "github.com/google/uuid", "v1.3.0", true},
		{"https://proxy.golang.org/golang.org/x/sys/@v/v0.1.0.mod", "golang.org/x/sys", "v0.1.0", true},
		{"https://proxy.golang.org/github.com/google/uuid/@v/list", "", "", false},
		{"https://proxy.golang.org/invalid/path", "", "", false},
		{"invalid-url-\x00", "", "", false},
	}

	for _, tc := range tests {
		mod, ver, ok := r.parseProxyURL(tc.url)
		if ok != tc.ok {
			t.Errorf("Expected ok=%v for %s, got %v", tc.ok, tc.url, ok)
			continue
		}
		if ok {
			if mod != tc.module {
				t.Errorf("Expected module %s, got %s", tc.module, mod)
			}
			if ver != tc.version {
				t.Errorf("Expected version %s, got %s", tc.version, ver)
			}
		}
	}
}
