package network

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/sbomit/sbomit/pkg/resolver"
)

// Maven repositories and the hosts Gradle resolves plugins from.
var javaNetworkDomains = []string{
	"repo.maven.apache.org",
	"repo1.maven.org",
	"plugins.gradle.org",
	"plugins-artifacts.gradle.org",
	"jitpack.io",
	"dl.google.com",
	"oss.sonatype.org",
	"central.sonatype.com",
}

// javaRepoRoots are the path segments a repository is served under, searched
// by last occurrence (Google's is at dl.google.com/dl/android/maven2/).
var javaRepoRoots = []string{"/maven2/", "/m2/"}

type JavaNetworkResolver struct {
	// <group as path>/<artifact>/<version>/<artifact>-<version>.<ext>
	coordRe *regexp.Regexp

	// Gradle's plugin portal adds a sha256 directory before the filename.
	hashedRe *regexp.Regexp
}

func NewJavaNetworkResolver() *JavaNetworkResolver {
	return &JavaNetworkResolver{
		coordRe: regexp.MustCompile(
			`^((?:[^/]+/)+)([^/]+)/([^/]+)/([^/]+)\.(?:jar|pom|aar|war)$`),
		hashedRe: regexp.MustCompile(
			`^((?:[^/]+/)+)([^/]+)/([^/]+)/[0-9a-f]{40,64}/([^/]+)\.(?:jar|pom|aar|war)$`),
	}
}

func (r *JavaNetworkResolver) Domains() []string { return javaNetworkDomains }

// Parse reads Maven coordinates from a repository request. The jar, aar or war
// is the artifact; the pom is metadata.
func (r *JavaNetworkResolver) Parse(_ NetworkConnection, ex NetworkExchange) (resolver.PackageInfo, bool, bool) {
	group, artifact, version, isArtifact, ok := r.parseURL(ex.URL)
	if !ok {
		return resolver.PackageInfo{}, false, false
	}

	return resolver.PackageInfo{
		Name:      artifact,
		Version:   version,
		Ecosystem: "maven",
		PURL:      fmt.Sprintf("pkg:maven/%s/%s@%s", group, artifact, version),
	}, isArtifact, true
}

// parseURL extracts Maven coordinates from a repository URL. isArtifact
// reports whether the URL names the packaged artifact rather than its pom.
func (r *JavaNetworkResolver) parseURL(rawURL string) (group, artifact, version string, isArtifact, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", false, false
	}

	// Each repository root, then the host root (jitpack).
	candidates := make([]string, 0, len(javaRepoRoots)+1)
	for _, root := range javaRepoRoots {
		if i := strings.LastIndex(u.Path, root); i >= 0 {
			candidates = append(candidates, u.Path[i+len(root):])
		}
	}
	candidates = append(candidates, strings.TrimPrefix(u.Path, "/"))

	for _, rest := range candidates {
		m := r.hashedRe.FindStringSubmatch(rest)
		if m == nil {
			m = r.coordRe.FindStringSubmatch(rest)
		}
		if m == nil {
			continue
		}

		groupPath, artifact, version, base := m[1], m[2], m[3], m[4]

		// The filename must repeat the artifact and version.
		if base != artifact+"-"+version {
			continue
		}

		group = strings.Trim(strings.ReplaceAll(strings.Trim(groupPath, "/"), "/", "."), ".")
		if group == "" {
			continue
		}

		return group, artifact, version, !strings.HasSuffix(u.Path, ".pom"), true
	}

	return "", "", "", false, false
}
