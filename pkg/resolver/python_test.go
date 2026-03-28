package resolver

import (
	"testing"
)

func TestPythonDistInfoResolve(t *testing.T) {
	r := NewPythonResolver()
	files := []FileInfo{
		{Path: "/usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", Hashes: map[string]string{"sha256": "abc123"}},
		{Path: "/usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/RECORD", Hashes: map[string]string{"sha256": "def456"}},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "requests" {
		t.Errorf("expected name 'requests', got %q", packages[0].Name)
	}
	if packages[0].Version != "2.31.0" {
		t.Errorf("expected version '2.31.0', got %q", packages[0].Version)
	}
	if packages[0].PURL != "pkg:pypi/requests@2.31.0" {
		t.Errorf("expected PURL 'pkg:pypi/requests@2.31.0', got %q", packages[0].PURL)
	}
	if packages[0].Ecosystem != "pypi" {
		t.Errorf("expected ecosystem 'pypi', got %q", packages[0].Ecosystem)
	}
	if packages[0].FoundBy != "attestation:python" {
		t.Errorf("expected foundBy 'attestation:python', got %q", packages[0].FoundBy)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining files, got %d", len(remaining))
	}
}

func TestPythonEggInfoResolve(t *testing.T) {
	r := NewPythonResolver()
	files := []FileInfo{
		{Path: "/usr/lib/python3.11/site-packages/setuptools-69.0.3.egg-info/PKG-INFO", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "setuptools" {
		t.Errorf("expected name 'setuptools', got %q", packages[0].Name)
	}
	if packages[0].Version != "69.0.3" {
		t.Errorf("expected version '69.0.3', got %q", packages[0].Version)
	}
}

func TestPythonDistPackagesResolve(t *testing.T) {
	r := NewPythonResolver()
	files := []FileInfo{
		{Path: "/usr/lib/python3/dist-packages/certifi-2023.7.22.dist-info/METADATA", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "certifi" {
		t.Errorf("expected name 'certifi', got %q", packages[0].Name)
	}
}

func TestPythonNameNormalization(t *testing.T) {
	r := NewPythonResolver()
	files := []FileInfo{
		// Underscores in package name should be normalized to hyphens (PEP 503)
		{Path: "/env/lib/python3.11/site-packages/Flask_Cors-4.0.0.dist-info/METADATA", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "flask-cors" {
		t.Errorf("expected normalized name 'flask-cors', got %q", packages[0].Name)
	}
}

func TestPythonDeduplication(t *testing.T) {
	r := NewPythonResolver()
	files := []FileInfo{
		{Path: "/env/lib/python3.11/site-packages/werkzeug-3.0.1.dist-info/METADATA", Hashes: map[string]string{"sha256": "a"}},
		{Path: "/env/lib/python3.11/site-packages/werkzeug-3.0.1.dist-info/RECORD", Hashes: map[string]string{"sha256": "b"}},
		{Path: "/env/lib/python3.11/site-packages/werkzeug-3.0.1.dist-info/top_level.txt", Hashes: map[string]string{"sha256": "c"}},
		{Path: "/env/lib/python3.11/site-packages/werkzeug-3.0.1.dist-info/WHEEL", Hashes: map[string]string{"sha256": "d"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package (deduplicated), got %d", len(packages))
	}
}

func TestPythonMultiplePackages(t *testing.T) {
	r := NewPythonResolver()
	files := []FileInfo{
		{Path: "/env/lib/python3.11/site-packages/flask-3.0.0.dist-info/METADATA", Hashes: map[string]string{"sha256": "a"}},
		{Path: "/env/lib/python3.11/site-packages/werkzeug-3.0.1.dist-info/METADATA", Hashes: map[string]string{"sha256": "b"}},
		{Path: "/env/lib/python3.11/site-packages/jinja2-3.1.2.dist-info/METADATA", Hashes: map[string]string{"sha256": "c"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}

	names := map[string]bool{}
	for _, pkg := range packages {
		names[pkg.Name] = true
	}
	for _, expected := range []string{"flask", "werkzeug", "jinja2"} {
		if !names[expected] {
			t.Errorf("expected package %q not found", expected)
		}
	}
}

func TestPythonNonPythonFilesPassThrough(t *testing.T) {
	r := NewPythonResolver()
	files := []FileInfo{
		{Path: "/usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", Hashes: map[string]string{"sha256": "a"}},
		{Path: "/home/user/project/main.go", Hashes: map[string]string{"sha256": "b"}},
		{Path: "/home/user/project/src/app.rs", Hashes: map[string]string{"sha256": "c"}},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining files, got %d", len(remaining))
	}
}

// --- Package filter tests ---

func TestPythonPackageFilterSitePackages(t *testing.T) {
	filter := &pythonPackageFilter{packageName: "werkzeug", version: "3.0.1"}

	// Should match files under the package directory
	if !filter.Matches("/env/lib/python3.11/site-packages/werkzeug/routing/rules.py") {
		t.Error("expected werkzeug source file to match")
	}
	if !filter.Matches("/env/lib/python3.11/site-packages/werkzeug/__init__.py") {
		t.Error("expected werkzeug init file to match")
	}
	if !filter.Matches("/env/lib/python3.11/site-packages/werkzeug-3.0.1.dist-info/METADATA") {
		t.Error("expected werkzeug dist-info to match")
	}

	// Should NOT match unrelated packages
	if filter.Matches("/env/lib/python3.11/site-packages/flask/app.py") {
		t.Error("expected flask file to NOT match werkzeug filter")
	}
}

func TestPythonPackageFilterDistPackages(t *testing.T) {
	filter := &pythonPackageFilter{packageName: "certifi", version: "2023.7.22"}

	if !filter.Matches("/usr/lib/python3/dist-packages/certifi/core.py") {
		t.Error("expected dist-packages path to match")
	}
}

func TestPythonPackageFilterPrivateModule(t *testing.T) {
	// pytest installs as _pytest internally
	filter := &pythonPackageFilter{packageName: "pytest", version: "7.4.3"}

	if !filter.Matches("/env/lib/python3.11/site-packages/_pytest/config/__init__.py") {
		t.Error("expected _pytest (private variant) to match pytest filter")
	}
}

// --- NormalizePackageName tests ---

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Flask", "flask"},
		{"Flask_Cors", "flask-cors"},
		{"Jinja2", "jinja2"},
		{"my__package", "my-package"},
		{"UPPER_CASE", "upper-case"},
		{"already-normalized", "already-normalized"},
	}

	for _, tt := range tests {
		result := NormalizePackageName(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizePackageName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
