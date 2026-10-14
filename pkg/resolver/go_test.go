package resolver

import "testing"

func TestGoResolverResolvesModuleCacheDownloadFiles(t *testing.T) {
	r := NewGoResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{
			Path: "/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.6.0.mod",
			Hashes: map[string]string{
				"sha256": "abc123",
			},
		},
		{
			Path: "/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.6.0.ziphash",
			Hashes: map[string]string{
				"sha256": "def456",
			},
		},
		{Path: "/repo/main.go"},
	})

	if len(remaining) != 1 {
		t.Fatalf("expected one remaining file, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}

	pkg := packages[0]
	if pkg.PURL != "pkg:golang/github.com/BurntSushi/toml@v1.6.0" {
		t.Fatalf("unexpected PURL: %s", pkg.PURL)
	}
	if pkg.Name != "github.com/BurntSushi/toml" {
		t.Fatalf("unexpected package name: %s", pkg.Name)
	}
	if len(pkg.Hashes) != 0 {
		t.Fatalf("cache file hashes should not be promoted to package hashes: %#v", pkg.Hashes)
	}
}

func TestGoResolverAggregatesModuleCacheAndSourcePaths(t *testing.T) {
	r := NewGoResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go"},
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/pkg/errors/@v/v0.9.1.mod"},
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/pkg/errors/@v/v0.9.1.info"},
	})

	if len(remaining) != 0 {
		t.Fatalf("expected no remaining files, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].PURL != "pkg:golang/github.com/pkg/errors@v0.9.1" {
		t.Fatalf("unexpected PURL: %s", packages[0].PURL)
	}
}

func TestGoResolverEscapesPURLVersion(t *testing.T) {
	r := NewGoResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: "/home/user/go/pkg/mod/github.com/peterbourgon/diskv@v2.0.1+incompatible/diskv.go"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].PURL != "pkg:golang/github.com/peterbourgon/diskv@v2.0.1%2Bincompatible" {
		t.Fatalf("unexpected PURL: %s", packages[0].PURL)
	}
}

func TestDecodeGoModulePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.com/!burnt!sushi/toml", "github.com/BurntSushi/toml"},
		{"github.com/!azure/azure-sdk-for-go", "github.com/Azure/azure-sdk-for-go"},
		{"golang.org/x/sync", "golang.org/x/sync"},
		{"plain/lowercase", "plain/lowercase"},
		{"!a!b!c", "ABC"},
		{"trailing-bang!", "trailing-bang!"},
	}

	for _, tt := range tests {
		got := DecodeGoModulePath(tt.input)
		if got != tt.expected {
			t.Errorf("DecodeGoModulePath(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestEncodeGoModulePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.com/BurntSushi/toml", "github.com/!burnt!sushi/toml"},
		{"github.com/Azure/azure-sdk-for-go", "github.com/!azure/azure-sdk-for-go"},
		{"golang.org/x/sync", "golang.org/x/sync"},
		{"ABC", "!a!b!c"},
	}

	for _, tt := range tests {
		got := encodeGoModulePath(tt.input)
		if got != tt.expected {
			t.Errorf("encodeGoModulePath(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestGoModulePathVariants(t *testing.T) {
	if variants := goModulePathVariants(""); len(variants) != 0 {
		t.Fatalf("expected empty variants for empty input, got: %v", variants)
	}

	variants := goModulePathVariants("github.com/BurntSushi/toml")
	expected := map[string]bool{
		"github.com/BurntSushi/toml":   true,
		"github.com/!burnt!sushi/toml": true,
	}

	for _, v := range variants {
		delete(expected, v)
	}
	if len(expected) > 0 {
		t.Errorf("missing expected variants: %v", expected)
	}
}

func TestGoPackageFilterMatches(t *testing.T) {
	r := NewGoResolver()

	packages := []PackageInfo{
		{
			Name:      "github.com/BurntSushi/toml",
			Version:   "v1.3.2",
			Ecosystem: "golang",
		},
		{
			Name:      "other-ecosystem",
			Version:   "1.0.0",
			Ecosystem: "npm",
		},
	}

	filters := r.CreateFileFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter (ignoring non-golang package), got %d", len(filters))
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/home/user/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/decode.go", true},
		{"/home/user/go/pkg/mod/github.com/burntsushi/toml@v1.3.2/decode.go", true},
		{"/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.3.2.mod", true},
		{"/home/user/go/pkg/mod/cache/download/github.com/!burnt!sushi/toml/@v/v1.3.2.zip", true},
		// Different version
		{"/home/user/go/pkg/mod/github.com/!burnt!sushi/toml@v1.4.0/decode.go", false},
		// Different module
		{"/home/user/go/pkg/mod/github.com/spf13/cobra@v1.3.2/command.go", false},
		// Non-go module path
		{"/workspace/src/github.com/BurntSushi/toml/decode.go", false},
	}

	for _, tt := range tests {
		matched := filters[0].Matches(tt.path)
		if matched != tt.expected {
			t.Errorf("filter match for %q = %v, expected %v", tt.path, matched, tt.expected)
		}
	}
}
