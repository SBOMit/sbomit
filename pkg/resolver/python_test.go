package resolver

import (
	"testing"
)

func TestPythonResolverName(t *testing.T) {
	r := NewPythonResolver()
	if r.Name() != "python" {
		t.Errorf("Expected name 'python', got '%s'", r.Name())
	}
}

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Flask", "flask"},
		{"requests-oauthlib", "requests-oauthlib"},
		{"Jinja2_abc", "jinja2-abc"},
		{"foo--bar", "foo-bar"},
	}

	for _, test := range tests {
		actual := NormalizePackageName(test.input)
		if actual != test.expected {
			t.Errorf("Expected '%s', got '%s'", test.expected, actual)
		}
	}
}

func TestPythonResolverResolve(t *testing.T) {
	r := NewPythonResolver()

	files := []FileInfo{
		{Path: "usr/lib/python3/dist-packages/requests-2.25.1.egg-info/PKG-INFO"},
		{Path: "venv/lib/python3.9/site-packages/Flask-1.1.2.dist-info/METADATA"},
		{Path: "src/main.py"},
	}

	pkgs, remaining := r.Resolve(files)

	if len(pkgs) != 2 {
		t.Errorf("Expected 2 packages resolved, got %d", len(pkgs))
	}
	if len(remaining) != 1 {
		t.Errorf("Expected 1 file remaining, got %d", len(remaining))
	}

	if remaining[0].Path != "src/main.py" {
		t.Errorf("Expected remaining file 'src/main.py', got '%s'", remaining[0].Path)
	}

	foundFlask := false
	for _, p := range pkgs {
		if p.Name == "flask" {
			foundFlask = true
			if p.Version != "1.1.2" {
				t.Errorf("Expected flask version '1.1.2', got '%s'", p.Version)
			}
		}
	}
	if !foundFlask {
		t.Errorf("Flask package not found in resolved packages")
	}
}

func TestPythonPackageFilterMatches(t *testing.T) {
	filter := &pythonPackageFilter{
		packageName: "flask",
		version:     "1.1.2",
	}

	if !filter.Matches("venv/lib/python3.9/site-packages/flask/app.py") {
		t.Errorf("Expected match for flask")
	}
	if filter.Matches("venv/lib/python3.9/site-packages/requests/api.py") {
		t.Errorf("Did not expect match for requests")
	}
	if filter.Matches("src/main.py") {
		t.Errorf("Did not expect match for src file")
	}
}
