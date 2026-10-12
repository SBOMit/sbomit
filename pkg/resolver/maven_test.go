package resolver

import (
	"testing"
)

func TestMavenResolverResolvesLocalRepositoryJars(t *testing.T) {
	r := NewMavenResolver()

	files := []FileInfo{
		{
			Path: "/root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
		},
		{
			Path: "/root/.m2/repository/com/google/guava/guava/32.1.2-jre/guava-32.1.2-jre.pom",
		},
		// Metadata sentinel files starting with non-digits must be skipped
		{
			Path: "/root/.m2/repository/org/apache/commons/commons-lang3/_remote.repositories",
		},
		{
			Path: "/root/.m2/repository/org/apache/commons/commons-lang3/maven-metadata-central.xml",
		},
		{
			Path: "/workspace/src/App.java",
		},
	}

	packages, remaining := r.Resolve(files)

	if len(packages) != 2 {
		t.Fatalf("expected 2 resolved maven packages, got %d", len(packages))
	}

	pkgsByPURL := make(map[string]PackageInfo)
	for _, p := range packages {
		pkgsByPURL[p.PURL] = p
	}

	commons, ok := pkgsByPURL["pkg:maven/org.apache.commons/commons-lang3@3.12.0"]
	if !ok {
		t.Fatalf("expected commons-lang3 package resolved, got %+v", packages)
	}
	if commons.Name != "commons-lang3" || commons.Version != "3.12.0" || commons.Ecosystem != "maven" {
		t.Errorf("unexpected commons-lang3 details: %+v", commons)
	}

	guava, ok := pkgsByPURL["pkg:maven/com.google.guava/guava@32.1.2-jre"]
	if !ok {
		t.Fatalf("expected guava package resolved, got %+v", packages)
	}
	if guava.Name != "guava" || guava.Version != "32.1.2-jre" || guava.Ecosystem != "maven" {
		t.Errorf("unexpected guava details: %+v", guava)
	}

	foundAppJava := false
	for _, rem := range remaining {
		if rem.Path == "/workspace/src/App.java" {
			foundAppJava = true
		}
	}
	if !foundAppJava {
		t.Errorf("expected /workspace/src/App.java to remain unresolved")
	}
}

func TestMavenPackageFilterMatches(t *testing.T) {
	r := NewMavenResolver()

	packages := []PackageInfo{
		{
			Name:      "commons-lang3",
			Version:   "3.12.0",
			Ecosystem: "maven",
			PURL:      "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
		},
	}

	filters := r.CreateFileFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected 1 maven package filter, got %d", len(filters))
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar", true},
		{"/root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom", true},
		{"/root/.m2/repository/org/apache/commons/commons-lang3/3.11/commons-lang3-3.11.jar", false},
		{"/workspace/commons-lang3.jar", false},
	}

	for _, tt := range tests {
		matched := filters[0].Matches(tt.path)
		if matched != tt.expected {
			t.Errorf("filter match for %q = %v, expected %v", tt.path, matched, tt.expected)
		}
	}
}
