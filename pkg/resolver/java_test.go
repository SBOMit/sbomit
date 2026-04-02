package resolver

import (
	"reflect"
	"testing"
)

func TestJavaResolver_Resolve(t *testing.T) {
	r := NewJavaResolver()

	tests := []struct {
		name            string
		files           []FileInfo
		expectPackages  []PackageInfo
		expectRemaining int
	}{
		{
			name: "resolves Maven jar from .m2 repository — multi-segment group",
			files: []FileInfo{
				{Path: "/root/.m2/repository/org/springframework/spring-core/6.1.0/spring-core-6.1.0.jar"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "spring-core",
					Version:   "6.1.0",
					Ecosystem: "maven",
					PURL:      "pkg:maven/org.springframework/spring-core@6.1.0",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves Maven jar from .m2 repository — single-segment group",
			files: []FileInfo{
				{Path: "/root/.m2/repository/junit/junit/4.13.2/junit-4.13.2.jar"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "junit",
					Version:   "4.13.2",
					Ecosystem: "maven",
					PURL:      "pkg:maven/junit/junit@4.13.2",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves Maven jar from .m2 repository — three-segment group",
			files: []FileInfo{
				{Path: "/root/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.jar"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "guava",
					Version:   "32.0.0-jre",
					Ecosystem: "maven",
					PURL:      "pkg:maven/com.google.guava/guava@32.0.0-jre",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves Maven jar with hyphenated artifactId",
			files: []FileInfo{
				{Path: "/root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "commons-lang3",
					Version:   "3.12.0",
					Ecosystem: "maven",
					PURL:      "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves Maven .pom file (not just .jar)",
			files: []FileInfo{
				{Path: "/root/.m2/repository/io/grpc/grpc-core/1.62.2/grpc-core-1.62.2.pom"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "grpc-core",
					Version:   "1.62.2",
					Ecosystem: "maven",
					PURL:      "pkg:maven/io.grpc/grpc-core@1.62.2",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "deduplicates .jar and .pom from same coordinate",
			files: []FileInfo{
				{Path: "/root/.m2/repository/junit/junit/4.13.2/junit-4.13.2.jar"},
				{Path: "/root/.m2/repository/junit/junit/4.13.2/junit-4.13.2.pom"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "junit",
					Version:   "4.13.2",
					Ecosystem: "maven",
					PURL:      "pkg:maven/junit/junit@4.13.2",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves Gradle cache jar",
			files: []FileInfo{
				{Path: "/root/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/32.0.0-jre/abc123hash/guava-32.0.0-jre.jar"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "guava",
					Version:   "32.0.0-jre",
					Ecosystem: "maven",
					PURL:      "pkg:maven/com.google.guava/guava@32.0.0-jre",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves multiple distinct Maven packages",
			files: []FileInfo{
				{Path: "/root/.m2/repository/org/springframework/spring-core/6.1.0/spring-core-6.1.0.jar"},
				{Path: "/root/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.jar"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "spring-core",
					Version:   "6.1.0",
					Ecosystem: "maven",
					PURL:      "pkg:maven/org.springframework/spring-core@6.1.0",
					FoundBy:   "attestation:java",
				},
				{
					Name:      "guava",
					Version:   "32.0.0-jre",
					Ecosystem: "maven",
					PURL:      "pkg:maven/com.google.guava/guava@32.0.0-jre",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "passes non-Java paths to remaining files",
			files: []FileInfo{
				{Path: "/usr/lib/python3/site-packages/requests-2.28.0.dist-info/METADATA"},
				{Path: "/usr/local/cargo/registry/src/index.crates.io-abc123/serde-1.0.0/src/lib.rs"},
			},
			expectPackages:  nil,
			expectRemaining: 2,
		},
		{
			name: "mixed Java and non-Java paths",
			files: []FileInfo{
				{Path: "/root/.m2/repository/junit/junit/4.13.2/junit-4.13.2.jar"},
				{Path: "/usr/lib/python3/site-packages/requests-2.28.0.dist-info/METADATA"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "junit",
					Version:   "4.13.2",
					Ecosystem: "maven",
					PURL:      "pkg:maven/junit/junit@4.13.2",
					FoundBy:   "attestation:java",
				},
			},
			expectRemaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages, remaining := r.Resolve(tt.files)

			if len(packages) != len(tt.expectPackages) {
				t.Fatalf("expected %d packages, got %d: %+v", len(tt.expectPackages), len(packages), packages)
			}

			// Compare by PURL to avoid map-iteration ordering flakiness
			byPURL := make(map[string]PackageInfo, len(packages))
			for _, pkg := range packages {
				pkg.Hashes = nil
				byPURL[pkg.PURL] = pkg
			}
			for _, want := range tt.expectPackages {
				got, ok := byPURL[want.PURL]
				if !ok {
					t.Errorf("expected package %q not found in results", want.PURL)
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("package %q mismatch.\nGot:  %+v\nWant: %+v", want.PURL, got, want)
				}
			}

			if len(remaining) != tt.expectRemaining {
				t.Errorf("expected %d remaining files, got %d", tt.expectRemaining, len(remaining))
			}
		})
	}
}

func TestJavaResolver_CreateFileFilters(t *testing.T) {
	r := NewJavaResolver()

	packages := []PackageInfo{
		{
			Name:      "spring-core",
			Version:   "6.1.0",
			Ecosystem: "maven",
			PURL:      "pkg:maven/org.springframework/spring-core@6.1.0",
		},
		{
			Name:      "guava",
			Version:   "32.0.0-jre",
			Ecosystem: "maven",
			PURL:      "pkg:maven/com.google.guava/guava@32.0.0-jre",
		},
	}

	filters := r.CreateFileFilters(packages)
	if len(filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(filters))
	}

	tests := []struct {
		path    string
		matches bool
	}{
		// Maven paths for spring-core
		{"/root/.m2/repository/org/springframework/spring-core/6.1.0/spring-core-6.1.0.jar", true},
		{"/root/.m2/repository/org/springframework/spring-core/6.1.0/spring-core-6.1.0.pom", true},
		// Maven paths for guava
		{"/root/.m2/repository/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.jar", true},
		// Gradle path for guava
		{"/root/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/32.0.0-jre/abc123/guava-32.0.0-jre.jar", true},
		// Different version — should not match
		{"/root/.m2/repository/com/google/guava/guava/31.0.0-jre/guava-31.0.0-jre.jar", false},
		// Unrelated path
		{"/usr/lib/python3/site-packages/requests-2.28.0.dist-info/METADATA", false},
	}

	for _, tt := range tests {
		matched := false
		for _, f := range filters {
			if f.Matches(tt.path) {
				matched = true
				break
			}
		}
		if matched != tt.matches {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, matched, tt.matches)
		}
	}
}
