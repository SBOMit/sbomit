package resolver

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sbomit/sbomit/pkg/attestation"
)

// mavenPathRe matches <groupId as path>/<artifactId>/<version>/<filename>
// below a repository root, which can be anywhere (-Dmaven.repo.local).
// mavenCoords requires the filename to repeat artifact and version.
var mavenPathRe = regexp.MustCompile(
	`^((?:[^/]+/)+)([^/]+)/([0-9][^/]*)/([^/]+)$`)

// mavenRepoRoots are the directory names a Maven repository is rooted at.
var mavenRepoRoots = []string{"/.m2/repository/", "/repository/", "/maven2/", "/m2/"}

// mavenSnapshotRe matches a deployed snapshot filename: Maven replaces
// "SNAPSHOT" with a timestamp, so 1.0-SNAPSHOT/ holds
// widget-1.0-20260101.123456-7.jar. It captures "widget-1.0", the part before
// the timestamp, to compare against the directory.
var mavenSnapshotRe = regexp.MustCompile(`^(.+?)-[0-9]{8}\.[0-9]{6}-[0-9]+(?:[.\-].*)?$`)

// gradlePathRe matches Gradle's module cache:
//
//	.../modules-2/files-2.1/<group>/<artifact>/<version>/<sha1 of file>/<filename>
//
// Gradle resolves Maven coordinates, so these are pkg:maven packages.
var gradlePathRe = regexp.MustCompile(
	`/modules-2/files-2\.1/([^/]+)/([^/]+)/([^/]+)/([0-9a-f]{40})/([^/]+)$`)

// gradleCoords returns the coordinates and the file's SHA-1 for a path in
// Gradle's module cache.
func gradleCoords(p string) (group, artifact, version, sha1 string, ok bool) {
	m := gradlePathRe.FindStringSubmatch(p)
	if m == nil {
		return "", "", "", "", false
	}
	return m[1], m[2], m[3], m[4], true
}

// mavenCoords returns the coordinates for a path in a Maven repository at any
// root. The filename must start with "<artifact>-<version>" from its
// directories (commons-lang3/3.12.0/commons-lang3-3.12.0.jar), which also
// skips Maven's own files such as _remote.repositories. Go's regexp cannot
// compare one part of a match with another, so that check is in code.
func mavenCoords(p string) (group, artifact, version string, ok bool) {
	for _, root := range mavenRepoRoots {
		// Last occurrence: a root name can also appear earlier in the path,
		// e.g. Tycho's cache under repository/.cache/.
		idx := strings.LastIndex(p, root)
		if idx < 0 {
			continue
		}

		m := mavenPathRe.FindStringSubmatch(p[idx+len(root):])
		if m == nil {
			continue
		}
		groupPath, artifact, version, base := m[1], m[2], m[3], m[4]

		if !mavenFilenameMatches(base, artifact, version) {
			continue
		}

		group = strings.Trim(strings.ReplaceAll(strings.Trim(groupPath, "/"), "/", "."), ".")
		if group == "" {
			continue
		}
		return group, artifact, version, true
	}

	return "", "", "", false
}

// mavenFilenameMatches reports whether a filename matches the artifact and
// version of its directory: a-1.0.jar, a-1.0.pom, a-1.0.jar.sha1,
// a-1.0-sources.jar, or a deployed snapshot of 1.0-SNAPSHOT.
func mavenFilenameMatches(base, artifact, version string) bool {
	stem := artifact + "-" + version
	if base == stem || strings.HasPrefix(base, stem+".") || strings.HasPrefix(base, stem+"-") {
		return true
	}

	// A deployed snapshot: the part before the timestamp must equal
	// "<artifact>-<version>" with -SNAPSHOT removed.
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return false
	}
	m := mavenSnapshotRe.FindStringSubmatch(base)
	if m == nil {
		return false
	}
	return m[1] == artifact+"-"+strings.TrimSuffix(version, "-SNAPSHOT")
}

type JavaResolver struct{}

func NewJavaResolver() *JavaResolver { return &JavaResolver{} }

func (r *JavaResolver) Name() string { return "java" }

func (r *JavaResolver) Resolve(files []FileInfo) ([]PackageInfo, []FileInfo) {
	g := newGroup()
	var remaining []FileInfo

	// Gradle's cache puts each file in a directory named after its SHA-1.
	// Recorded per path here, then added to each package's artifact below.
	sha1ByPath := map[string]string{}

	for _, f := range files {
		if isP2Path(f.Path) {
			remaining = append(remaining, f)
			continue
		}

		group, artifact, version, ok := mavenCoords(f.Path)
		pkgmgr := "maven"

		if !ok {
			var sha1 string
			group, artifact, version, sha1, ok = gradleCoords(f.Path)
			if !ok {
				remaining = append(remaining, f)
				continue
			}
			pkgmgr = "gradle"
			sha1ByPath[f.Path] = sha1
		}

		purl := fmt.Sprintf("pkg:maven/%s/%s@%s", group, artifact, version)

		g.add(purl, PackageInfo{
			Name:      artifact,
			Version:   version,
			Ecosystem: "maven",
			PURL:      purl,
			PkgMgr:    pkgmgr,
		}, f)
	}

	packages, rest := g.finish(rankMavenEvidence, isMavenArtifact)

	// Add the sha1 from the Gradle cache path to each package's artifact.
	for i, pkg := range packages {
		if pkg.Artifact == nil {
			continue
		}
		if sha1, found := sha1ByPath[pkg.Artifact.Path]; found {
			packages[i].Artifact.Digests = attestation.AddDigest(pkg.Artifact.Digests, "sha1", sha1)
			attestation.SortDigests(packages[i].Artifact.Digests)
		}
	}

	return packages, append(remaining, rest...)
}

// isP2Path reports whether a path is in Tycho's p2 cache
// (<root>/p2/osgi/bundle/...). Its paths look like Maven's but carry no real Maven
// coordinates, so it is left unclaimed.
func isP2Path(p string) bool {
	for _, root := range mavenRepoRoots {
		if strings.Contains(p, root+"p2/") {
			return true
		}
	}
	return false
}

// isMavenArtifact reports whether a path is the packaged artifact, not its pom,
// checksum or signature.
func isMavenArtifact(p string) bool {
	base := strings.ToLower(p)
	for _, ext := range []string{".jar", ".war", ".ear", ".aar"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// rankMavenEvidence prefers the artifact, then the pom or a zip assembly.
func rankMavenEvidence(p string) int {
	base := strings.ToLower(p)

	// Checksums and signatures beside the artifact (.jar.sha1, .jar.asc)
	// rank lowest.
	for _, ext := range []string{".sha1", ".sha256", ".sha512", ".md5", ".asc"} {
		if strings.HasSuffix(base, ext) {
			return 0
		}
	}

	if isMavenArtifact(p) {
		return 3
	}
	if strings.HasSuffix(base, ".zip") {
		return 2
	}

	if strings.HasSuffix(base, ".pom") {
		return 2
	}

	return 1
}

func (r *JavaResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter
	for _, pkg := range packages {
		if pkg.Ecosystem != "maven" {
			continue
		}
		// pkg:maven/{group}/{artifact}@{version}
		rest := strings.TrimPrefix(pkg.PURL, "pkg:maven/")
		atIdx := strings.LastIndex(rest, "@")
		if atIdx < 0 {
			continue
		}
		groupAndArtifact := rest[:atIdx]
		version := rest[atIdx+1:]
		slashIdx := strings.LastIndex(groupAndArtifact, "/")
		if slashIdx < 0 {
			continue
		}
		group := groupAndArtifact[:slashIdx]
		artifact := groupAndArtifact[slashIdx+1:]
		groupAsPath := strings.ReplaceAll(group, ".", "/")

		// The version directory under any root, and its Gradle-cache form.
		mavenNeedle := fmt.Sprintf("/%s/%s/%s/", groupAsPath, artifact, version)
		gradleNeedle := fmt.Sprintf("/files-2.1/%s/%s/%s/", group, artifact, version)

		filters = append(filters, OwnershipFilter{
			PURL: pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool {
				return strings.Contains(p.Clean, mavenNeedle) ||
					strings.Contains(p.Clean, gradleNeedle)
			}),
		})
	}
	return filters
}
