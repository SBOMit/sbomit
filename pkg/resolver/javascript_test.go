package resolver

import (
	"testing"
)

func TestJavaScriptResolverName(t *testing.T) {
	r := NewJavaScriptResolver()
	if r.Name() != "javascript" {
		t.Errorf("Expected name 'javascript', got '%s'", r.Name())
	}
}

func TestNormalizeNpmPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Express", "express"},
		{"@Types/Node", "@types/node"},
		{"  lodash  ", "lodash"},
	}

	for _, test := range tests {
		actual := NormalizeNpmPackageName(test.input)
		if actual != test.expected {
			t.Errorf("Expected '%s', got '%s'", test.expected, actual)
		}
	}
}

func TestExtractPnpmVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"express@4.17.1", "4.17.1"},
		{"@types/node@14.14.31", "14.14.31"},
		{"react@17.0.2(react-dom@17.0.2)", "17.0.2"},
		{"invalid", ""},
		{"@types/node@", ""},
	}

	for _, test := range tests {
		actual := extractPnpmVersion(test.input)
		if actual != test.expected {
			t.Errorf("For '%s', expected '%s', got '%s'", test.input, test.expected, actual)
		}
	}
}

func TestJavaScriptResolverResolve(t *testing.T) {
	r := NewJavaScriptResolver()

	files := []FileInfo{
		{Path: "node_modules/.pnpm/express@4.17.1/node_modules/express/index.js"},
		{Path: "node_modules/.pnpm/@types+node@14.14.31/node_modules/@types/node/index.d.ts"},
		{Path: "src/main.js"},
	}

	pkgs, remaining := r.Resolve(files)

	if len(pkgs) != 2 {
		t.Errorf("Expected 2 packages resolved, got %d", len(pkgs))
	}
	if len(remaining) != 1 {
		t.Errorf("Expected 1 file remaining, got %d", len(remaining))
	}

	if remaining[0].Path != "src/main.js" {
		t.Errorf("Expected remaining file 'src/main.js', got '%s'", remaining[0].Path)
	}

	foundExpress := false
	for _, p := range pkgs {
		if p.Name == "express" {
			foundExpress = true
			if p.Version != "4.17.1" {
				t.Errorf("Expected express version '4.17.1', got '%s'", p.Version)
			}
		}
	}
	if !foundExpress {
		t.Errorf("Express package not found in resolved packages")
	}
}

func TestJsPackageFilterMatches(t *testing.T) {
	filter := &jsPackageFilter{
		packageName: "express",
		version:     "4.17.1",
	}

	if !filter.Matches("project/node_modules/.pnpm/express@4.17.1/node_modules/express/index.js") {
		t.Errorf("Expected match for express")
	}
	if filter.Matches("node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/index.js") {
		t.Errorf("Did not expect match for lodash")
	}
	if filter.Matches("src/index.js") {
		t.Errorf("Did not expect match for src file")
	}
}
