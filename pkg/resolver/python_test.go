package resolver

import (
	"testing"
)

func TestPythonNormalizePackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Flask", "flask"},
		{"Flask_Cors", "flask-cors"},
		{"oslo.messaging", "oslo.messaging"},
		{"hello--world", "hello-world"},
		{"a_b_c", "a-b-c"},
	}

	for _, tt := range tests {
		got := NormalizePackageName(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizePackageName(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestPythonResolverResolvesDistAndEggInfo(t *testing.T) {
	r := NewPythonResolver()

	files := []FileInfo{
		{
			Path: "/opt/venv/lib/python3.11/site-packages/urllib3-2.0.7.dist-info/METADATA",
			Hashes: map[string]string{
				"sha256": "file-hash-should-not-be-promoted",
			},
		},
		{
			Path: "/opt/venv/lib/python3.11/site-packages/urllib3-2.0.7.dist-info/RECORD",
		},
		{
			Path: "/usr/lib/python3/dist-packages/setuptools-59.6.0.egg-info/PKG-INFO",
		},
		{
			Path: "/workspace/script.py",
		},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 2 {
		t.Fatalf("expected 2 resolved packages, got %d", len(packages))
	}
	if len(remaining) != 1 || remaining[0].Path != "/workspace/script.py" {
		t.Fatalf("expected 1 unresolved file /workspace/script.py, got %+v", remaining)
	}

	pkgsByPURL := make(map[string]PackageInfo)
	for _, p := range packages {
		pkgsByPURL[p.PURL] = p
	}

	urllib3, ok := pkgsByPURL["pkg:pypi/urllib3@2.0.7"]
	if !ok {
		t.Fatalf("expected urllib3 package resolved, got %+v", packages)
	}
	if urllib3.Name != "urllib3" || urllib3.Version != "2.0.7" || urllib3.Ecosystem != "pypi" {
		t.Errorf("unexpected urllib3 package details: %+v", urllib3)
	}

	// Verify package hashes are not populated from individual member files (Issue #65 fix)
	if len(urllib3.Hashes) != 0 {
		t.Errorf("expected package hashes to remain empty for member file scans, got %+v", urllib3.Hashes)
	}

	setuptools, ok := pkgsByPURL["pkg:pypi/setuptools@59.6.0"]
	if !ok {
		t.Fatalf("expected setuptools package resolved, got %+v", packages)
	}
	if setuptools.Name != "setuptools" || setuptools.Version != "59.6.0" {
		t.Errorf("unexpected setuptools package details: %+v", setuptools)
	}
}

func TestPythonPackageFilterMatches(t *testing.T) {
	r := NewPythonResolver()

	packages := []PackageInfo{
		{Name: "pytest", Version: "7.4.0", Ecosystem: "pypi"},
		{Name: "flask-cors", Version: "4.0.0", Ecosystem: "pypi"},
	}

	filters := r.CreateFileFilters(packages)
	if len(filters) != 2 {
		t.Fatalf("expected 2 package filters, got %d", len(filters))
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/venv/lib/python3.11/site-packages/pytest/config.py", true},
		{"/venv/lib/python3.11/site-packages/_pytest/mark.py", true},
		{"/venv/lib/python3.11/site-packages/flask_cors/extension.py", true},
		{"/venv/lib/python3.11/site-packages/requests/api.py", false},
		{"/workspace/pytest/test_local.py", false},
	}

	for _, tt := range tests {
		matched := false
		for _, f := range filters {
			if f.Matches(tt.path) {
				matched = true
				break
			}
		}
		if matched != tt.expected {
			t.Errorf("filter match for %q = %v, expected %v", tt.path, matched, tt.expected)
		}
	}
}
