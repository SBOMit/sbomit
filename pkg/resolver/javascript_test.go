package resolver

import (
	"testing"
)

// --- pnpm resolution (existing behavior, regression tests) ---

func TestPnpmResolve(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/home/user/project/node_modules/.pnpm/express@4.18.2/node_modules/express/index.js", Hashes: map[string]string{"sha256": "abc123"}},
		{Path: "/home/user/project/node_modules/.pnpm/express@4.18.2/node_modules/express/lib/router.js", Hashes: map[string]string{"sha256": "def456"}},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "express" {
		t.Errorf("expected name 'express', got %q", packages[0].Name)
	}
	if packages[0].Version != "4.18.2" {
		t.Errorf("expected version '4.18.2', got %q", packages[0].Version)
	}
	if packages[0].PURL != "pkg:npm/express@4.18.2" {
		t.Errorf("expected PURL 'pkg:npm/express@4.18.2', got %q", packages[0].PURL)
	}
	if packages[0].Ecosystem != "npm" {
		t.Errorf("expected ecosystem 'npm', got %q", packages[0].Ecosystem)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining files, got %d", len(remaining))
	}
}

func TestPnpmScopedResolve(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/home/user/project/node_modules/.pnpm/@babel+core@7.24.0/node_modules/@babel/core/lib/index.js", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "@babel/core" {
		t.Errorf("expected name '@babel/core', got %q", packages[0].Name)
	}
	if packages[0].Version != "7.24.0" {
		t.Errorf("expected version '7.24.0', got %q", packages[0].Version)
	}
}

func TestPnpmDeduplication(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js", Hashes: map[string]string{"sha256": "a"}},
		{Path: "/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.min.js", Hashes: map[string]string{"sha256": "b"}},
		{Path: "/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/core.js", Hashes: map[string]string{"sha256": "c"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package (deduplicated), got %d", len(packages))
	}
	if packages[0].Name != "lodash" {
		t.Errorf("expected 'lodash', got %q", packages[0].Name)
	}
}

// --- Standard npm / Yarn classic resolution (new) ---

func TestNpmStandardResolve(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/home/user/project/node_modules/express/package.json", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "express" {
		t.Errorf("expected name 'express', got %q", packages[0].Name)
	}
	if packages[0].Version != "unknown" {
		t.Errorf("expected version 'unknown', got %q", packages[0].Version)
	}
	if packages[0].PURL != "pkg:npm/express@unknown" {
		t.Errorf("expected PURL 'pkg:npm/express@unknown', got %q", packages[0].PURL)
	}
	if packages[0].FoundBy != "attestation:javascript:npm" {
		t.Errorf("expected foundBy 'attestation:javascript:npm', got %q", packages[0].FoundBy)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining files, got %d", len(remaining))
	}
}

func TestNpmScopedResolve(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/project/node_modules/@babel/core/package.json", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "@babel/core" {
		t.Errorf("expected name '@babel/core', got %q", packages[0].Name)
	}
	if packages[0].Version != "unknown" {
		t.Errorf("expected version 'unknown', got %q", packages[0].Version)
	}
}

func TestNpmDoesNotMatchPnpmPaths(t *testing.T) {
	r := NewJavaScriptResolver()
	// This path should be matched by pnpm extractor (with version), NOT npm extractor
	files := []FileInfo{
		{Path: "/project/node_modules/.pnpm/express@4.18.2/node_modules/express/package.json", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	// Should have the real version from pnpm, not "unknown" from npm extractor
	if packages[0].Version != "4.18.2" {
		t.Errorf("expected pnpm-extracted version '4.18.2', got %q (npm extractor may have matched instead)", packages[0].Version)
	}
	if packages[0].FoundBy != "attestation:javascript:pnpm" {
		t.Errorf("expected foundBy 'attestation:javascript:pnpm', got %q", packages[0].FoundBy)
	}
}

func TestNpmSkipsHiddenPackages(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/project/node_modules/.package-lock.json", Hashes: map[string]string{"sha256": "abc"}},
		{Path: "/project/node_modules/.cache/something/package.json", Hashes: map[string]string{"sha256": "def"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 0 {
		t.Errorf("expected 0 packages (hidden dirs should be skipped), got %d", len(packages))
	}
}

func TestNpmNonPackageJsonNotResolved(t *testing.T) {
	r := NewJavaScriptResolver()
	// Random files under node_modules should NOT be resolved (only package.json triggers detection)
	files := []FileInfo{
		{Path: "/project/node_modules/express/lib/router.js", Hashes: map[string]string{"sha256": "abc"}},
		{Path: "/project/node_modules/express/index.js", Hashes: map[string]string{"sha256": "def"}},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 0 {
		t.Errorf("expected 0 packages (non-package.json files), got %d", len(packages))
	}
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining files, got %d", len(remaining))
	}
}

func TestNpmMultiplePackages(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/project/node_modules/express/package.json", Hashes: map[string]string{"sha256": "a"}},
		{Path: "/project/node_modules/lodash/package.json", Hashes: map[string]string{"sha256": "b"}},
		{Path: "/project/node_modules/@types/node/package.json", Hashes: map[string]string{"sha256": "c"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}

	names := map[string]bool{}
	for _, pkg := range packages {
		names[pkg.Name] = true
	}
	for _, expected := range []string{"express", "lodash", "@types/node"} {
		if !names[expected] {
			t.Errorf("expected package %q not found", expected)
		}
	}
}

// --- Yarn Berry PnP resolution (new) ---

func TestYarnBerryResolve(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/project/.yarn/cache/react-npm-18.2.0-1eae08fee2-88b02f2e3e.zip", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "react" {
		t.Errorf("expected name 'react', got %q", packages[0].Name)
	}
	if packages[0].Version != "18.2.0" {
		t.Errorf("expected version '18.2.0', got %q", packages[0].Version)
	}
	if packages[0].PURL != "pkg:npm/react@18.2.0" {
		t.Errorf("expected PURL 'pkg:npm/react@18.2.0', got %q", packages[0].PURL)
	}
	if packages[0].FoundBy != "attestation:javascript:yarn-berry" {
		t.Errorf("expected foundBy 'attestation:javascript:yarn-berry', got %q", packages[0].FoundBy)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining files, got %d", len(remaining))
	}
}

func TestYarnBerryScopedResolve(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		{Path: "/project/.yarn/cache/@types-node-npm-20.11.5-b807d46a42-6e3487cf0f.zip", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "@types/node" {
		t.Errorf("expected name '@types/node', got %q", packages[0].Name)
	}
	if packages[0].Version != "20.11.5" {
		t.Errorf("expected version '20.11.5', got %q", packages[0].Version)
	}
}

func TestYarnBerryMultiWordScoped(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		// @tanstack/react-query → @tanstack-react-query in yarn cache
		{Path: "/project/.yarn/cache/@tanstack-react-query-npm-5.17.9-aabb112233-ccdd445566.zip", Hashes: map[string]string{"sha256": "abc"}},
	}

	packages, _ := r.Resolve(files)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "@tanstack/react-query" {
		t.Errorf("expected name '@tanstack/react-query', got %q", packages[0].Name)
	}
	if packages[0].Version != "5.17.9" {
		t.Errorf("expected version '5.17.9', got %q", packages[0].Version)
	}
}

// --- Package filter tests ---

func TestJsPackageFilterPnpm(t *testing.T) {
	filter := &jsPackageFilter{packageName: "express", version: "4.18.2"}

	// Should match files under the pnpm store for this package
	if !filter.Matches("/project/node_modules/.pnpm/express@4.18.2/node_modules/express/lib/router.js") {
		t.Error("expected pnpm path to match")
	}

	// Should not match a different version
	if filter.Matches("/project/node_modules/.pnpm/express@4.17.0/node_modules/express/lib/router.js") {
		t.Error("expected different version pnpm path to NOT match")
	}
}

func TestJsPackageFilterNpm(t *testing.T) {
	filter := &jsPackageFilter{packageName: "express", version: "unknown"}

	// Should match standard npm paths
	if !filter.Matches("/project/node_modules/express/lib/router.js") {
		t.Error("expected standard npm path to match")
	}
	if !filter.Matches("/project/node_modules/express/index.js") {
		t.Error("expected standard npm path to match")
	}

	// Should not match .pnpm internal paths (those have their own filter logic)
	if filter.Matches("/project/node_modules/.pnpm/express@4.18.2/node_modules/express/index.js") {
		t.Error("expected pnpm internal path to NOT match via npm filter")
	}
}

func TestJsPackageFilterNpmScoped(t *testing.T) {
	filter := &jsPackageFilter{packageName: "@babel/core", version: "unknown"}

	if !filter.Matches("/project/node_modules/@babel/core/lib/index.js") {
		t.Error("expected scoped npm path to match")
	}
}

func TestJsPackageFilterYarnBerry(t *testing.T) {
	filter := &jsPackageFilter{packageName: "react", version: "18.2.0"}

	if !filter.Matches("/project/.yarn/cache/react-npm-18.2.0-1eae08fee2-88b02f2e3e.zip") {
		t.Error("expected yarn berry cache path to match")
	}

	// Should not match a different version
	if filter.Matches("/project/.yarn/cache/react-npm-17.0.1-deadbeef12-abcdef1234.zip") {
		t.Error("expected different version yarn berry path to NOT match")
	}
}

// --- Mixed ecosystem test ---

func TestMixedJsEcosystems(t *testing.T) {
	r := NewJavaScriptResolver()
	files := []FileInfo{
		// pnpm package
		{Path: "/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js", Hashes: map[string]string{"sha256": "a"}},
		// npm package
		{Path: "/project/node_modules/express/package.json", Hashes: map[string]string{"sha256": "b"}},
		// yarn berry package
		{Path: "/project/.yarn/cache/react-npm-18.2.0-1eae08fee2-88b02f2e3e.zip", Hashes: map[string]string{"sha256": "c"}},
		// Non-JS file
		{Path: "/project/src/main.go", Hashes: map[string]string{"sha256": "d"}},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining file, got %d", len(remaining))
	}
	if remaining[0].Path != "/project/src/main.go" {
		t.Errorf("expected remaining file to be main.go, got %q", remaining[0].Path)
	}

	// Verify each package manager was used
	foundByMap := map[string]bool{}
	for _, pkg := range packages {
		foundByMap[pkg.FoundBy] = true
	}
	for _, expected := range []string{
		"attestation:javascript:pnpm",
		"attestation:javascript:npm",
		"attestation:javascript:yarn-berry",
	} {
		if !foundByMap[expected] {
			t.Errorf("expected foundBy %q not found", expected)
		}
	}
}

// --- Helper function tests ---

func TestNormalizeNpmPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Express", "express"},
		{"  lodash  ", "lodash"},
		{"@Babel/Core", "@babel/core"},
		{"REACT", "react"},
	}

	for _, tt := range tests {
		result := NormalizeNpmPackageName(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeNpmPackageName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestDecodeYarnCacheName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"react", "react"},
		{"lodash", "lodash"},
		{"@types-node", "@types/node"},
		{"@babel-core", "@babel/core"},
		{"@tanstack-react-query", "@tanstack/react-query"},
	}

	for _, tt := range tests {
		result := decodeYarnCacheName(tt.input)
		if result != tt.expected {
			t.Errorf("decodeYarnCacheName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractPnpmVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"express@4.18.2", "4.18.2"},
		{"@babel+core@7.24.0", "7.24.0"},
		{"react@18.2.0(react-dom@18.2.0)", "18.2.0"},
		{"", ""},
		{"no-version", ""},
	}

	for _, tt := range tests {
		result := extractPnpmVersion(tt.input)
		if result != tt.expected {
			t.Errorf("extractPnpmVersion(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
