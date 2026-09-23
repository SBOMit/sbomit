package resolver

import (
	"fmt"
	"regexp"
	"strings"
)

// mavenPathRe matches paths inside a local Maven repository.
//
// Maven stores artifacts at:
//
//	~/.m2/repository/<groupId-as-path>/<artifactId>/<version>/<filename>
//
// e.g. /root/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
//
// Groups:
//
//	1 — group ID as path  ("org/apache/commons")
//	2 — artifact ID       ("commons-lang3")
//	3 — version directory ("3.12.0")
var mavenPathRe = regexp.MustCompile(`\.m2/repository/(.+)/([^/]+)/([^/]+)/[^/]+$`)

type MavenResolver struct{}

func NewMavenResolver() *MavenResolver { return &MavenResolver{} }

func (r *MavenResolver) Name() string { return "maven" }

func (r *MavenResolver) Resolve(files []FileInfo) ([]PackageInfo, []FileInfo) {
	g := newGroup()
	var remaining []FileInfo

	for _, f := range files {
		if !strings.Contains(f.Path, "/.m2/repository/") {
			remaining = append(remaining, f)
			continue
		}

		m := mavenPathRe.FindStringSubmatch(f.Path)
		if m == nil {
			remaining = append(remaining, f)
			continue
		}

		groupPath := m[1]
		artifact := m[2]
		version := m[3]

		// Version must start with a digit — rejects metadata sentinels like
		// _remote.repositories, maven-metadata.xml directories, etc.
		if len(version) == 0 || version[0] < '0' || version[0] > '9' {
			remaining = append(remaining, f)
			continue
		}

		group := strings.ReplaceAll(groupPath, "/", ".")
		group = strings.Trim(group, ".")

		purl := fmt.Sprintf("pkg:maven/%s/%s@%s", group, artifact, version)

		g.add(purl, PackageInfo{
			Name:      artifact,
			Version:   version,
			Ecosystem: "maven",
			PURL:      purl,
			FoundBy:   "attestation:maven",
		}, f)
	}

	packages, rest := g.finish(rankMavenEvidence)
	return packages, append(remaining, rest...)
}

// rankMavenEvidence prefers the published artifact, then its pom. A version
// directory also holds checksums, signatures and Maven's own bookkeeping, none
// of which identify the artifact.
func rankMavenEvidence(p string) int {
	base := strings.ToLower(p)

	// Checksums and signatures sit beside the artifact and share its stem, so
	// test them before the packaging extensions.
	for _, ext := range []string{".sha1", ".sha256", ".sha512", ".md5", ".asc"} {
		if strings.HasSuffix(base, ext) {
			return 0
		}
	}

	for _, ext := range []string{".jar", ".war", ".ear", ".aar", ".zip"} {
		if strings.HasSuffix(base, ext) {
			return 3
		}
	}

	if strings.HasSuffix(base, ".pom") {
		return 2
	}

	return 1
}

func (r *MavenResolver) OwnershipFilters(packages []PackageInfo) []OwnershipFilter {
	var filters []OwnershipFilter
	for _, pkg := range packages {
		if pkg.Ecosystem != "maven" {
			continue
		}
		// Reconstruct directory prefix from PURL components.
		// PURL: pkg:maven/{group}/{artifact}@{version}
		// Prefix: /.m2/repository/{group-as-path}/{artifact}/{version}/
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
		prefix := fmt.Sprintf("/.m2/repository/%s/%s/%s/", groupAsPath, artifact, version)
		filters = append(filters, OwnershipFilter{
			PURL:    pkg.PURL,
			Matcher: MatcherFunc(func(p Path) bool { return strings.Contains(p.Clean, prefix) }),
		})
	}
	return filters
}
