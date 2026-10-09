package resolver

import (
	"testing"
)

type mockResolver struct {
	name string
}

func (m *mockResolver) Name() string { return m.name }
func (m *mockResolver) Resolve(files []FileInfo) ([]PackageInfo, []FileInfo) {
	var pkgs []PackageInfo
	var remaining []FileInfo

	for _, f := range files {
		if f.Path == "resolve_me" {
			pkgs = append(pkgs, PackageInfo{Name: "mock-pkg", Version: "1.0", PURL: "pkg:mock/mock-pkg@1.0", Ecosystem: "mock"})
		} else {
			remaining = append(remaining, f)
		}
	}
	return pkgs, remaining
}

type mockFilterer struct {
	mockResolver
}

func (m *mockFilterer) CreateFileFilters(packages []PackageInfo) []PackageFileFilter {
	return []PackageFileFilter{&mockPackageFilter{}}
}

type mockPackageFilter struct{}

func (m *mockPackageFilter) Matches(path string) bool {
	return path == "filtered_pkg_file"
}

func TestResolverChain(t *testing.T) {
	chain := NewResolverChain()

	// Should have default resolvers (Python, Go, Rust, JS, Maven)
	if len(chain.resolvers) != 5 {
		t.Errorf("Expected 5 default resolvers, got %d", len(chain.resolvers))
	}

	// Add custom resolver
	chain.AddResolver(&mockResolver{name: "test-mock"})
	if len(chain.resolvers) != 6 {
		t.Errorf("Expected 6 resolvers after addition, got %d", len(chain.resolvers))
	}
}

func TestResolveAll(t *testing.T) {
	chain := &ResolverChain{
		resolvers: []Resolver{
			&mockFilterer{mockResolver{name: "mock"}},
		},
		filter: NewFileFilter(), // Default file filter
	}

	files := []FileInfo{
		{Path: "resolve_me"},         // Will be resolved by mockResolver
		{Path: "keep_me"},            // Unresolved file
		{Path: "filtered_pkg_file"},  // Will be filtered out by PackageFileFilterer
		{Path: "/tmp/go-build/skip"}, // Filtered out initially by standard FileFilter
	}

	res := chain.ResolveAll(files)

	// Check packages
	if len(res.Packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(res.Packages))
	}
	if res.Packages[0].Name != "mock-pkg" {
		t.Errorf("Expected 'mock-pkg', got '%s'", res.Packages[0].Name)
	}

	// Check remaining files
	if len(res.Files) != 1 {
		t.Fatalf("Expected 1 remaining file, got %d", len(res.Files))
	}
	if res.Files[0].Path != "keep_me" {
		t.Errorf("Expected 'keep_me', got '%s'", res.Files[0].Path)
	}
}
