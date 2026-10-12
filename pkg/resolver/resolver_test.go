package resolver

import (
	"testing"
)

func TestResolverChainResolveAll(t *testing.T) {
	chain := NewResolverChain()

	inputFiles := []FileInfo{
		// Should be excluded by initial file filter
		{Path: "/workspace/.git/HEAD"},
		{Path: "/app/__pycache__/app.cpython-311.pyc"},

		// Python dependency and member file
		{Path: "/venv/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA"},
		{Path: "/venv/lib/python3.11/site-packages/requests/api.py"},

		// Go dependency and member file
		{Path: "/home/user/go/pkg/mod/github.com/google/uuid@v1.6.0/uuid.go"},
		{Path: "/home/user/go/pkg/mod/cache/download/github.com/google/uuid/@v/v1.6.0.mod"},

		// Unresolved workspace file (should remain in result.Files)
		{Path: "/workspace/src/custom_logic.py"},
	}

	result := chain.ResolveAll(inputFiles)

	if len(result.Packages) != 2 {
		t.Fatalf("expected 2 resolved packages (requests and uuid), got %d", len(result.Packages))
	}

	packagesByPURL := make(map[string]PackageInfo)
	for _, p := range result.Packages {
		packagesByPURL[p.PURL] = p
	}

	if _, ok := packagesByPURL["pkg:pypi/requests@2.31.0"]; !ok {
		t.Errorf("expected requests package in resolved list: %+v", result.Packages)
	}
	if _, ok := packagesByPURL["pkg:golang/github.com/google/uuid@v1.6.0"]; !ok {
		t.Errorf("expected uuid package in resolved list: %+v", result.Packages)
	}

	// Verify member files (/venv/.../requests/api.py and /home/user/.../uuid.go)
	// were filtered out by filterPackageFiles and only truly unresolved files remain.
	if len(result.Files) != 1 {
		t.Fatalf("expected exactly 1 unresolved file, got %d: %+v", len(result.Files), result.Files)
	}
	if result.Files[0].Path != "/workspace/src/custom_logic.py" {
		t.Errorf("expected unresolved file to be /workspace/src/custom_logic.py, got %s", result.Files[0].Path)
	}
}

func TestResolverChainDeduplication(t *testing.T) {
	chain := NewResolverChain()

	// Two dist-info files for the same package
	inputFiles := []FileInfo{
		{Path: "/venv/lib/python3.11/site-packages/urllib3-2.0.7.dist-info/METADATA"},
		{Path: "/venv/lib/python3.11/site-packages/urllib3-2.0.7.dist-info/RECORD"},
	}

	result := chain.ResolveAll(inputFiles)

	if len(result.Packages) != 1 {
		t.Fatalf("expected 1 deduplicated package, got %d", len(result.Packages))
	}
	if result.Packages[0].PURL != "pkg:pypi/urllib3@2.0.7" {
		t.Errorf("unexpected package: %+v", result.Packages[0])
	}
}
