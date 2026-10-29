package resolver

import (
	"sort"
	"strings"
	"testing"
)

const m2Repo = "/root/.m2/repository"

func mavenPURLs(packages []PackageInfo) []string {
	out := make([]string, 0, len(packages))
	for _, p := range packages {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

func TestJavaResolverResolvesLocalRepository(t *testing.T) {
	r := NewJavaResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: m2Repo + "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"},
		{Path: m2Repo + "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"},
		{Path: m2Repo + "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar.sha1"},
		{Path: m2Repo + "/org/apache/commons/commons-lang3/3.12.0/_remote.repositories"},
	})

	got := mavenPURLs(packages)
	if len(got) != 1 || got[0] != "pkg:maven/org.apache.commons/commons-lang3@3.12.0" {
		t.Fatalf("expected pkg:maven/org.apache.commons/commons-lang3@3.12.0, got %v", got)
	}

	// The jar outranks the pom; checksum files rank lowest.
	want := m2Repo + "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
	if len(packages[0].Locations) != 1 || packages[0].Locations[0] != want {
		t.Fatalf("expected the jar to be cited, got %v", packages[0].Locations)
	}
}

func TestJavaResolverRejectsNonVersionDirectories(t *testing.T) {
	r := NewJavaResolver()

	packages, remaining := r.Resolve([]FileInfo{
		{Path: m2Repo + "/org/apache/commons/commons-lang3/maven-metadata.xml"},
		{Path: m2Repo + "/org/apache/commons/commons-lang3/resolver-status.properties"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages, got %v", mavenPURLs(packages))
	}
	if len(remaining) != 2 {
		t.Fatalf("expected both metadata paths to flow on, got %d", len(remaining))
	}
}

func TestJavaResolverAttributesArtifactFiles(t *testing.T) {
	r := NewJavaResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: m2Repo + "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"},
	})

	filters := r.OwnershipFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected one ownership filter, got %d", len(filters))
	}

	owned := m2Repo + "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
	if !filters[0].Matcher.Matches(NewPath(owned)) {
		t.Fatalf("expected the artifact to own %s", owned)
	}

	foreign := m2Repo + "/org/apache/commons/commons-lang3/3.13.0/commons-lang3-3.13.0.pom"
	if filters[0].Matcher.Matches(NewPath(foreign)) {
		t.Fatalf("did not expect 3.12.0 to own %s", foreign)
	}
}

// The repository can be rooted anywhere (-Dmaven.repo.local).
func TestJavaResolverResolvesRepositoryAtAnyRoot(t *testing.T) {
	r := NewJavaResolver()

	for _, root := range []string{
		"/home/jake/javacache/google-java-format/repository",
		"/root/.m2/repository",
		"/opt/ci/m2",
		"/srv/mirror/maven2",
	} {
		packages, _ := r.Resolve([]FileInfo{
			{Path: root + "/biz/aQute/bnd/biz.aQute.bndlib/7.2.3/biz.aQute.bndlib-7.2.3.jar"},
		})

		got := mavenPURLs(packages)
		want := "pkg:maven/biz.aQute.bnd/biz.aQute.bndlib@7.2.3"
		if len(got) != 1 || got[0] != want {
			t.Errorf("root %s: expected %s, got %v", root, want, got)
		}
	}
}

// A path whose filename doesn't match its directory is declined.
func TestJavaResolverRequiresTheFilenameToCorroborate(t *testing.T) {
	r := NewJavaResolver()

	packages, remaining := r.Resolve([]FileInfo{
		// Right shape, wrong artifact in the filename.
		{Path: m2Repo + "/org/apache/commons/commons-lang3/3.12.0/guava-33.0.0.jar"},
		// A four-deep path in a repository that is not an artifact directory.
		{Path: m2Repo + "/org/apache/commons/commons-lang3/3.12.0/_remote.repositories"},
		// No repository root marker anywhere.
		{Path: "/home/jake/src/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"},
	})

	if len(packages) != 0 {
		t.Fatalf("expected no packages, got %v", mavenPURLs(packages))
	}
	if len(remaining) != 3 {
		t.Fatalf("expected all three paths to flow on, got %d", len(remaining))
	}
}

// Deployed snapshots are named with a timestamp instead of -SNAPSHOT.
func TestJavaResolverResolvesTimestampedSnapshots(t *testing.T) {
	r := NewJavaResolver()

	dir := m2Repo + "/com/example/widget/1.0-SNAPSHOT"
	packages, _ := r.Resolve([]FileInfo{
		{Path: dir + "/widget-1.0-20260101.123456-7.jar"},
		{Path: dir + "/widget-1.0-20260101.123456-7.pom"},
		{Path: dir + "/maven-metadata-local.xml"},
	})

	got := mavenPURLs(packages)
	want := "pkg:maven/com.example/widget@1.0-SNAPSHOT"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected %s, got %v", want, got)
	}

	// The jar is still the artifact, even under a rewritten name.
	if !strings.HasSuffix(packages[0].Locations[0], ".jar") {
		t.Fatalf("expected the jar to be cited, got %v", packages[0].Locations)
	}
}

// A non-timestamped snapshot is the local-install form, where the filename
// keeps the -SNAPSHOT version verbatim.
func TestJavaResolverResolvesLocalSnapshots(t *testing.T) {
	r := NewJavaResolver()

	dir := m2Repo + "/com/example/widget/1.0-SNAPSHOT"
	packages, _ := r.Resolve([]FileInfo{
		{Path: dir + "/widget-1.0-SNAPSHOT.jar"},
	})

	got := mavenPURLs(packages)
	want := "pkg:maven/com.example/widget@1.0-SNAPSHOT"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected %s, got %v", want, got)
	}
}

// Only the jar is the artifact, not the pom, checksums or signatures.
func TestJavaResolverTakesPackageDigestFromJar(t *testing.T) {
	dir := m2Repo + "/org/apache/commons/commons-lang3/3.12.0"

	fromJar, _ := NewJavaResolver().Resolve([]FileInfo{
		{Path: dir + "/commons-lang3-3.12.0.jar", Digests: []Digest{{Algorithm: "sha256", Value: "archive-digest"}}},
		{Path: dir + "/commons-lang3-3.12.0.pom", Digests: []Digest{{Algorithm: "sha256", Value: "pom-digest"}}},
	})
	if len(fromJar) != 1 {
		t.Fatalf("expected one package, got %d", len(fromJar))
	}
	if got := artifactDigest(fromJar[0], "sha256"); got != "archive-digest" {
		t.Fatalf("expected the jar digest, got %q", got)
	}

	pomOnly, _ := NewJavaResolver().Resolve([]FileInfo{
		{Path: dir + "/commons-lang3-3.12.0.pom", Digests: []Digest{{Algorithm: "sha256", Value: "pom-digest"}}},
	})
	if len(pomOnly) != 1 {
		t.Fatalf("expected one package, got %d", len(pomOnly))
	}
	if pomOnly[0].Artifact != nil {
		t.Fatalf("expected no package digest from a pom, got %v", pomOnly[0].Artifact)
	}
}

const gradleCache = "/home/jake/javacache/apktool/gradle-home/caches/modules-2/files-2.1"

// Gradle's module cache yields pkg:maven packages.
func TestJavaResolverResolvesGradleModuleCache(t *testing.T) {
	r := NewJavaResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: gradleCache + "/antlr/antlr/2.7.7/83cd2cd674a217ade95a4bb83a8a14f351f48bd0/antlr-2.7.7.jar"},
		{Path: gradleCache + "/antlr/antlr/2.7.7/52f15b99911ab8b8bc8744675f5cf1994a626fb8/antlr-2.7.7.pom"},
		{Path: gradleCache + "/com.android.tools/r8/9.1.31/ff16ffc4d4090123456789012345678901234567/r8-9.1.31.jar"},
	})

	got := mavenPURLs(packages)
	want := []string{"pkg:maven/antlr/antlr@2.7.7", "pkg:maven/com.android.tools/r8@9.1.31"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

// Gradle's cache directory names give the artifact's sha1.
func TestJavaResolverTakesGradleDigestFromThePath(t *testing.T) {
	r := NewJavaResolver()

	const sha = "83cd2cd674a217ade95a4bb83a8a14f351f48bd0"
	packages, _ := r.Resolve([]FileInfo{
		{Path: gradleCache + "/antlr/antlr/2.7.7/" + sha + "/antlr-2.7.7.jar"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if got := artifactDigest(packages[0], "sha1"); got != sha {
		t.Fatalf("expected the path's sha1, got %q", got)
	}

	// An attested digest is still preferred: it covers more algorithms and
	// does not depend on trusting the path.
	attested, _ := r.Resolve([]FileInfo{
		{
			Path:    gradleCache + "/antlr/antlr/2.7.7/" + sha + "/antlr-2.7.7.jar",
			Digests: []Digest{{Algorithm: "sha256", Value: "attested-digest"}},
		},
	})
	if got := artifactDigest(attested[0], "sha256"); got != "attested-digest" {
		t.Fatalf("expected the attested digest to win, got %v", attested[0].Artifact)
	}
}

// A pom has no artifact digest to take, from the path or anywhere else.
func TestJavaResolverLeavesGradlePomDigestEmpty(t *testing.T) {
	r := NewJavaResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: gradleCache + "/antlr/antlr/2.7.7/52f15b99911ab8b8bc8744675f5cf1994a626fb8/antlr-2.7.7.pom"},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if packages[0].Artifact != nil {
		t.Fatalf("expected no digest from a pom, got %v", packages[0].Artifact)
	}
}

func TestJavaResolverAttributesGradleCacheFiles(t *testing.T) {
	r := NewJavaResolver()

	packages, _ := r.Resolve([]FileInfo{
		{Path: gradleCache + "/antlr/antlr/2.7.7/83cd2cd674a217ade95a4bb83a8a14f351f48bd0/antlr-2.7.7.jar"},
	})

	filters := r.OwnershipFilters(packages)
	if len(filters) != 1 {
		t.Fatalf("expected one ownership filter, got %d", len(filters))
	}

	// A different SHA-1 directory under the same coordinates is the pom.
	owned := gradleCache + "/antlr/antlr/2.7.7/52f15b99911ab8b8bc8744675f5cf1994a626fb8/antlr-2.7.7.pom"
	if !filters[0].Matcher.Matches(NewPath(owned)) {
		t.Fatalf("expected antlr 2.7.7 to own %s", owned)
	}

	foreign := gradleCache + "/antlr/antlr/2.7.8/52f15b99911ab8b8bc8744675f5cf1994a626fb8/antlr-2.7.8.pom"
	if filters[0].Matcher.Matches(NewPath(foreign)) {
		t.Fatalf("did not expect 2.7.7 to own %s", foreign)
	}
}

// The artifact can be a different file from the one cited.
func TestJavaResolverTakesDigestFromAnArtifactThatIsNotTheCitation(t *testing.T) {
	dir := m2Repo + "/com/example/widget/1.0"

	// A packaging type that ranks below .pom as evidence, with a jar present:
	// the citation and the digest source differ.
	packages, _ := NewJavaResolver().Resolve([]FileInfo{
		{Path: dir + "/widget-1.0.pom", Digests: []Digest{{Algorithm: "sha256", Value: "pom-digest"}}},
		{Path: dir + "/widget-1.0.jar.sha1", Digests: []Digest{{Algorithm: "sha256", Value: "checksum-digest"}}},
		{Path: dir + "/widget-1.0.jar", Digests: []Digest{{Algorithm: "sha256", Value: "jar-digest"}}},
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if got := artifactDigest(packages[0], "sha256"); got != "jar-digest" {
		t.Fatalf("expected the jar digest, got %q", got)
	}
}

// Tycho's p2 cache has Maven-shaped paths but no Maven coordinates.
func TestJavaResolverDoesNotInventCoordinatesForP2Bundles(t *testing.T) {
	const bundle = "/home/jake/generate_att/javacache/google-java-format/repository/p2/osgi/bundle/" +
		"com.ibm.icu/54.1.1.v201501272100/com.ibm.icu-54.1.1.v201501272100.jar"

	packages, remaining := NewJavaResolver().Resolve([]FileInfo{{Path: bundle}})

	if len(packages) != 0 {
		t.Fatalf("expected no package for a p2 bundle, got %v", packages)
	}
	if len(remaining) != 1 {
		t.Fatalf("the bundle path must flow on, got %v", remaining)
	}
}

func TestJavaResolverNamesTheLayoutsPackageManager(t *testing.T) {
	packages, _ := NewJavaResolver().Resolve([]FileInfo{
		{Path: "/root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"},
		{Path: gradleCache + "/antlr/antlr/2.7.7/83cd2cd674a217ade95a4bb83a8a14f351f48bd0/antlr-2.7.7.jar"},
	})

	pkgmgrs := map[string]string{}
	for _, p := range packages {
		pkgmgrs[p.Name] = p.PkgMgr
	}
	if pkgmgrs["commons-lang3"] != "maven" || pkgmgrs["antlr"] != "gradle" {
		t.Fatalf("expected maven and gradle, got %v", pkgmgrs)
	}
}
