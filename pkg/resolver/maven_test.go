package resolver

import (
	"testing"
)

func TestMavenResolverName(t *testing.T) {
	r := NewMavenResolver()
	if r.Name() != "maven" {
		t.Errorf("Expected name 'maven', got '%s'", r.Name())
	}
}

func TestMavenResolverResolve(t *testing.T) {
	r := NewMavenResolver()

	files := []FileInfo{
		{Path: "/root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"},
		{Path: "/home/user/.m2/repository/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar"},
		{Path: "/root/.m2/repository/org/apache/maven-metadata.xml"}, // No version/digit
		{Path: "src/main/java/com/example/App.java"},
	}

	pkgs, remaining := r.Resolve(files)

	if len(pkgs) != 2 {
		t.Fatalf("Expected 2 packages resolved, got %d", len(pkgs))
	}
	if len(remaining) != 2 {
		t.Fatalf("Expected 2 files remaining, got %d", len(remaining))
	}

	foundCommons := false
	foundGuava := false
	for _, p := range pkgs {
		if p.Name == "commons-lang3" {
			foundCommons = true
			if p.Version != "3.12.0" {
				t.Errorf("Expected version 3.12.0, got %s", p.Version)
			}
			if p.PURL != "pkg:maven/org.apache.commons/commons-lang3@3.12.0" {
				t.Errorf("Unexpected PURL: %s", p.PURL)
			}
		} else if p.Name == "guava" {
			foundGuava = true
			if p.PURL != "pkg:maven/com.google.guava/guava@31.0.1-jre" {
				t.Errorf("Unexpected PURL: %s", p.PURL)
			}
		}
	}

	if !foundCommons || !foundGuava {
		t.Errorf("Failed to resolve all expected packages")
	}

	// Verify remaining files
	foundMeta := false
	foundSrc := false
	for _, rem := range remaining {
		if rem.Path == "/root/.m2/repository/org/apache/maven-metadata.xml" {
			foundMeta = true
		} else if rem.Path == "src/main/java/com/example/App.java" {
			foundSrc = true
		}
	}

	if !foundMeta || !foundSrc {
		t.Errorf("Expected remaining files not found")
	}
}

func TestMavenPackageFilterMatches(t *testing.T) {
	pkg := PackageInfo{
		Ecosystem: "maven",
		PURL:      "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
	}

	r := NewMavenResolver()
	filters := r.CreateFileFilters([]PackageInfo{pkg})

	if len(filters) != 1 {
		t.Fatalf("Expected 1 filter, got %d", len(filters))
	}

	filter := filters[0]

	if !filter.Matches("/root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar") {
		t.Errorf("Expected match for valid jar")
	}
	if filter.Matches("/root/.m2/repository/com/google/guava/guava/31.0.1-jre/guava.jar") {
		t.Errorf("Did not expect match for guava")
	}
}
