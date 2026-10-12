package resolver

import (
	"testing"
)

func TestNormalizeNpmPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  Express ", "express"},
		{"@Types/Node", "@types/node"},
		{"lodash", "lodash"},
	}

	for _, tt := range tests {
		got := NormalizeNpmPackageName(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeNpmPackageName(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractPnpmVersion(t *testing.T) {
	tests := []struct {
		segment  string
		expected string
	}{
		{"express@4.18.2", "4.18.2"},
		{"@types+node@20.5.0", "20.5.0"},
		{"react@18.2.0(react-dom@18.2.0)", "18.2.0"},
		{"invalid-segment", ""},
		{"pkg@", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractPnpmVersion(tt.segment)
		if got != tt.expected {
			t.Errorf("extractPnpmVersion(%q) = %q, expected %q", tt.segment, got, tt.expected)
		}
	}
}

func TestJavaScriptResolverResolve(t *testing.T) {
	r := NewJavaScriptResolver()

	files := []FileInfo{
		{Path: "node_modules/.pnpm/express@4.18.2/node_modules/express/lib/application.js"},
		{Path: "node_modules/.pnpm/@types+node@20.5.0/node_modules/@types/node/index.d.ts"},
		{Path: "src/index.js"},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}
	if len(remaining) != 1 || remaining[0].Path != "src/index.js" {
		t.Fatalf("expected 1 remaining file src/index.js, got %+v", remaining)
	}

	pkgsByPURL := make(map[string]PackageInfo)
	for _, p := range packages {
		pkgsByPURL[p.PURL] = p
	}

	exp, ok := pkgsByPURL["pkg:npm/express@4.18.2"]
	if !ok || exp.Name != "express" || exp.Version != "4.18.2" {
		t.Errorf("unexpected express package: %+v", exp)
	}

	nodeTypes, ok := pkgsByPURL["pkg:npm/@types/node@20.5.0"]
	if !ok || nodeTypes.Name != "@types/node" || nodeTypes.Version != "20.5.0" {
		t.Errorf("unexpected @types/node package: %+v", nodeTypes)
	}
}

func TestJavaScriptPackageFilterMatches(t *testing.T) {
	r := NewJavaScriptResolver()

	packages := []PackageInfo{
		{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		{Name: "@types/node", Version: "20.5.0", Ecosystem: "npm"},
	}

	filters := r.CreateFileFilters(packages)
	if len(filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(filters))
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/app/node_modules/.pnpm/express@4.18.2/node_modules/express/package.json", true},
		{"/app/node_modules/.pnpm/@types+node@20.5.0/node_modules/@types/node/index.d.ts", true},
		{"/app/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js", false},
		{"/app/src/express/custom.js", false},
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
