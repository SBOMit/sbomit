package resolver

import (
	"path"
	"regexp"
	"strings"
)

type JavaResolver struct {
	mavenRe  *regexp.Regexp
	gradleRe *regexp.Regexp
}

func NewJavaResolver() *JavaResolver {
	return &JavaResolver{
		mavenRe:  regexp.MustCompile(`\.m2/repository/(.+)/([^/]+)/([^/]+)/[^/]+-[^/]+\.(jar|pom|aar|war|ear)$`),
		gradleRe: regexp.MustCompile(`\.gradle/caches/modules-2/files-2\.1/([^/]+)/([^/]+)/([^/]+)/[^/]+/[^/]+\.(jar|pom|aar)$`),
	}
}

func (r *JavaResolver) Name() string {
	return "java"
}

func (r *JavaResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	seen := make(map[string]int)

	for _, f := range files {
		np := path.Clean(f.Path)

		if !r.isJavaPath(np) {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		groupID, artifactID, version, ok := r.extractCoordinates(np)
		if !ok {
			remainingFiles = append(remainingFiles, f)
			continue
		}

		key := groupID + ":" + artifactID + "@" + version
		if idx, already := seen[key]; already {
			for k, v := range f.Hashes {
				if _, exists := packages[idx].Hashes[k]; !exists {
					if packages[idx].Hashes == nil {
						packages[idx].Hashes = make(map[string]string)
					}
					packages[idx].Hashes[k] = v
				}
			}
			continue
		}

		purl := "pkg:maven/" + groupID + "/" + artifactID + "@" + version
		pkg := PackageInfo{
			Name:      artifactID,
			Version:   version,
			Ecosystem: "maven",
			PURL:      purl,
			Hashes:    f.Hashes,
			FoundBy:   "attestation:java",
		}
		seen[key] = len(packages)
		packages = append(packages, pkg)
	}

	return packages, remainingFiles
}

func (r *JavaResolver) CreateFileFilters(packages []PackageInfo) []PackageFileFilter {
	var filters []PackageFileFilter

	for _, pkg := range packages {
		if pkg.Ecosystem != "maven" {
			continue
		}

		rest := strings.TrimPrefix(pkg.PURL, "pkg:maven/")
		rest = strings.SplitN(rest, "@", 2)[0]
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			continue
		}

		filters = append(filters, &javaPackageFilter{
			groupID:    parts[0],
			artifactID: parts[1],
			version:    pkg.Version,
		})
	}

	return filters
}

type javaPackageFilter struct {
	groupID    string
	artifactID string
	version    string
}

func (f *javaPackageFilter) Matches(p string) bool {
	np := path.Clean(p)
	npLower := strings.ToLower(np)

	if !strings.Contains(npLower, "/.m2/repository/") && !strings.Contains(npLower, "/.gradle/caches/") {
		return false
	}

	groupPathLower := strings.ReplaceAll(strings.ToLower(f.groupID), ".", "/")
	artifactLower := strings.ToLower(f.artifactID)
	versionLower := strings.ToLower(f.version)

	if strings.Contains(npLower, "/.m2/repository/"+groupPathLower+"/"+artifactLower+"/"+versionLower+"/") {
		return true
	}

	if strings.Contains(npLower, "/.gradle/caches/modules-2/files-2.1/"+strings.ToLower(f.groupID)+"/"+artifactLower+"/"+versionLower+"/") {
		return true
	}

	return false
}

func (r *JavaResolver) isJavaPath(p string) bool {
	return strings.Contains(p, "/.m2/repository/") ||
		strings.Contains(p, "/.gradle/caches/modules-2/files-2.1/")
}

func (r *JavaResolver) extractCoordinates(p string) (groupID, artifactID, version string, ok bool) {
	if matches := r.mavenRe.FindStringSubmatch(p); len(matches) >= 4 {
		group := strings.ReplaceAll(matches[1], "/", ".")
		if group == "" || matches[2] == "" || matches[3] == "" {
			return "", "", "", false
		}
		return group, matches[2], matches[3], true
	}

	if matches := r.gradleRe.FindStringSubmatch(p); len(matches) >= 4 {
		return matches[1], matches[2], matches[3], true
	}

	return "", "", "", false
}
