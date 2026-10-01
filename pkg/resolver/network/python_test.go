package network

import (
	"testing"
)

func TestPythonNetworkResolverDomains(t *testing.T) {
	r := NewPythonNetworkResolver()
	domains := r.Domains()
	if len(domains) != 3 {
		t.Fatalf("Expected 3 domains, got %d", len(domains))
	}
}

func TestPythonNetworkResolverResolve(t *testing.T) {
	r := NewPythonNetworkResolver()

	conn := NetworkConnection{
		Hostname: "files.pythonhosted.org",
		IP:       "151.101.129.63",
		Exchanges: []NetworkExchange{
			{
				URL:        "https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz",
				StatusCode: 200,
				BodyHash:   "hash_req",
			},
			{
				URL:        "https://files.pythonhosted.org/packages/py3/F/Flask/Flask-2.2.3-py3-none-any.whl",
				StatusCode: 200,
			},
			{
				URL:        "https://pypi.org/pypi/urllib3/1.26.15/json",
				StatusCode: 200,
			},
			{
				URL:        "https://pypi.org/pypi/notfound/1.0/json",
				StatusCode: 404,
			},
		},
	}

	pkgs := r.Resolve(conn)

	if len(pkgs) != 3 {
		t.Fatalf("Expected 3 packages, got %d", len(pkgs))
	}

	foundRequests := false
	foundFlask := false
	foundUrllib3 := false

	for _, p := range pkgs {
		if p.Name == "requests" {
			foundRequests = true
			if p.Version != "2.31.0" {
				t.Errorf("Expected requests version 2.31.0, got %s", p.Version)
			}
			if p.Hashes["sha256"] != "hash_req" {
				t.Errorf("Expected hash_req, got %s", p.Hashes["sha256"])
			}
		}
		if p.Name == "flask" {
			foundFlask = true
			if p.Version != "2.2.3" {
				t.Errorf("Expected flask version 2.2.3, got %s", p.Version)
			}
		}
		if p.Name == "urllib3" {
			foundUrllib3 = true
			if p.Version != "1.26.15" {
				t.Errorf("Expected urllib3 version 1.26.15, got %s", p.Version)
			}
		}
	}

	if !foundRequests || !foundFlask || !foundUrllib3 {
		t.Errorf("Did not find all expected packages")
	}
}

func TestPythonParseURL(t *testing.T) {
	r := NewPythonNetworkResolver()

	tests := []struct {
		url     string
		name    string
		version string
		ok      bool
	}{
		{"https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz", "requests", "2.31.0", true},
		{"https://files.pythonhosted.org/packages/py3/F/Flask/Flask-2.2.3-py3-none-any.whl", "flask", "2.2.3", true},
		{"https://pypi.org/pypi/urllib3/1.26.15/json", "urllib3", "1.26.15", true},
		{"https://files.pythonhosted.org/packages/source/a/ansible_core/ansible-core-2.14.0.tar.gz", "ansible-core", "2.14.0", true}, // Normalize name
		{"https://pypi.org/simple/requests/", "", "", false},
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
