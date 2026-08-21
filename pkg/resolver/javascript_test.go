package resolver

import "testing"

func TestJavaScriptResolverResolvesPnpmLayout(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js"},
		{Path: "/project/node_modules/.pnpm/@babel+core@7.24.0/node_modules/@babel/core/index.js"},
	})

	if len(remaining) != 0 {
		t.Fatalf("expected no remaining files, got %d", len(remaining))
	}
	if len(packages) != 2 {
		t.Fatalf("expected two packages, got %d", len(packages))
	}

	if packages[0].Name != "lodash" || packages[0].Version != "4.17.21" {
		t.Fatalf("unexpected package: %s@%s", packages[0].Name, packages[0].Version)
	}
	if packages[0].PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("unexpected PURL: %s", packages[0].PURL)
	}
	if packages[1].Name != "@babel/core" || packages[1].Version != "7.24.0" {
		t.Fatalf("unexpected scoped package: %s@%s", packages[1].Name, packages[1].Version)
	}
	if packages[1].PURL != "pkg:npm/@babel/core@7.24.0" {
		t.Fatalf("unexpected PURL: %s", packages[1].PURL)
	}
}

func TestJavaScriptResolverResolvesNpmFlatLayout(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/project/node_modules/lodash/lodash.js"},
		{
			Path: "/project/node_modules/lodash/package.json",
			Hashes: map[string]string{
				"sha256": "abc123",
			},
		},
	})

	if len(remaining) != 0 {
		t.Fatalf("expected no remaining files, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}

	pkg := packages[0]
	if pkg.Name != "lodash" {
		t.Fatalf("unexpected package name: %s", pkg.Name)
	}
	if pkg.Version != "" {
		t.Fatalf("expected empty version for npm layout, got %q", pkg.Version)
	}
	if pkg.PURL != "pkg:npm/lodash" {
		t.Fatalf("unexpected PURL: %s", pkg.PURL)
	}
	if pkg.Ecosystem != "npm" || pkg.FoundBy != "attestation:javascript" {
		t.Fatalf("unexpected package metadata: %#v", pkg)
	}
	if len(pkg.Hashes) != 1 {
		t.Fatalf("expected first file hashes to be promoted, got %#v", pkg.Hashes)
	}
}

func TestJavaScriptResolverResolvesScopedPackages(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: "/project/node_modules/@types/node/fs.d.ts"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].Name != "@types/node" {
		t.Fatalf("unexpected package name: %s", packages[0].Name)
	}
	if packages[0].PURL != "pkg:npm/@types/node" {
		t.Fatalf("unexpected PURL: %s", packages[0].PURL)
	}
}

func TestJavaScriptResolverPrefersInnermostNestedPackage(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: "/project/node_modules/express/node_modules/lodash/lib.js"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].Name != "lodash" {
		t.Fatalf("expected innermost package lodash, got %s", packages[0].Name)
	}
}

func TestJavaScriptResolverDeduplicatesFilesOfSamePackage(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/project/node_modules/react/index.js"},
		{Path: "/project/node_modules/react/jsx-runtime.js"},
		{Path: "/project/node_modules/react/cjs/react.development.js"},
	})

	if len(remaining) != 0 {
		t.Fatalf("expected no remaining files, got %d", len(remaining))
	}
	if len(packages) != 1 {
		t.Fatalf("expected one deduplicated package, got %d", len(packages))
	}
}

func TestJavaScriptResolverSkipsNodeModulesInternals(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/project/node_modules/.bin/mocha"},
		{Path: "/project/node_modules/.package-lock.json"},
		{Path: "/project/node_modules/.pnpm/lock.yaml"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages from node_modules internals, got %d", len(packages))
	}
	if len(remaining) != 3 {
		t.Fatalf("expected internals to remain unresolved, got %d", len(remaining))
	}
}

func TestJavaScriptResolverMixedLayouts(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/project/node_modules/.pnpm/left-pad@1.3.0/node_modules/left-pad/index.js"},
		{Path: "/project/node_modules/underscore/underscore.js"},
		{Path: "/project/node_modules/@scope/util/index.js"},
	})

	if len(remaining) != 0 {
		t.Fatalf("expected no remaining files, got %d", len(remaining))
	}
	if len(packages) != 3 {
		t.Fatalf("expected three packages, got %d", len(packages))
	}

	byPURL := make(map[string]PackageInfo)
	for _, pkg := range packages {
		byPURL[pkg.PURL] = pkg
	}

	versioned, ok := byPURL["pkg:npm/left-pad@1.3.0"]
	if !ok || versioned.Version != "1.3.0" {
		t.Fatalf("missing versioned pnpm package: %#v", versioned)
	}
	if _, ok := byPURL["pkg:npm/underscore"]; !ok {
		t.Fatalf("missing unversioned npm package")
	}
	if _, ok := byPURL["pkg:npm/@scope/util"]; !ok {
		t.Fatalf("missing unversioned scoped npm package")
	}
}

func TestJavaScriptResolverPassesThroughNonJavaScriptPaths(t *testing.T) {
	r := NewJavaScriptResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: "/project/main.go"},
		{Path: "/project/requirements.txt"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages, got %d", len(packages))
	}
	if len(remaining) != 2 {
		t.Fatalf("expected files to pass through, got %d", len(remaining))
	}
}

func TestJSPackageFilterMatchesStandardNodeModulesPaths(t *testing.T) {
	f := &jsPackageFilter{packageName: "lodash"}

	if !f.Matches("/project/node_modules/lodash/lodash.js") {
		t.Fatal("expected filter to match standard npm layout path")
	}
	if f.Matches("/project/node_modules/express/index.js") {
		t.Fatal("expected filter not to match other packages")
	}
	if f.Matches("/project/src/index.js") {
		t.Fatal("expected filter not to match paths outside node_modules")
	}
}

func TestJSPackageFilterMatchesScopedPackagePaths(t *testing.T) {
	f := &jsPackageFilter{packageName: "@types/node"}

	if !f.Matches("/project/node_modules/@types/node/fs.d.ts") {
		t.Fatal("expected filter to match scoped package path")
	}
	if f.Matches("/project/node_modules/@types/react/index.d.ts") {
		t.Fatal("expected filter not to match other scoped packages")
	}
}

func TestJSPackageFilterRequiresVersionForPnpmStoreMatch(t *testing.T) {
	unversioned := &jsPackageFilter{packageName: "lodash"}
	if unversioned.Matches("/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js") {
		t.Fatal("expected unversioned filter not to match pnpm store paths")
	}

	versioned := &jsPackageFilter{packageName: "lodash", version: "4.17.21"}
	if !versioned.Matches("/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js") {
		t.Fatal("expected versioned filter to match matching pnpm store path")
	}
	if versioned.Matches("/project/node_modules/.pnpm/lodash@1.0.0/node_modules/lodash/lodash.js") {
		t.Fatal("expected versioned filter not to match different pnpm store version")
	}
}

func TestJSPackageFilterMatchesPnpmVirtualStoreWithPeerSuffix(t *testing.T) {
	f := &jsPackageFilter{packageName: "react", version: "18.2.0"}

	if !f.Matches("/project/node_modules/.pnpm/react@18.2.0(react-dom@18.2.0)/node_modules/react/index.js") {
		t.Fatal("expected filter to match pnpm store entry with peer suffix")
	}
}
