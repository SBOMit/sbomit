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
		// Matches: .../.m2/repository/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar
		// Group 1: path to group (com/google/guava)
		// Group 2: artifactId (guava)
		// Group 3: version (31.1-jre)
		// Group 4: filename (guava-31.1-jre)
		// Group 5: extension (jar|pom|war)
		mavenRe: regexp.MustCompile(`\.m2/repository/(.+)/([^/]+)/([^/]+)/([^/]+)\.(jar|pom|war)$`),

		// Matches: .../.gradle/caches/modules-2/files-2.1/com.google.guava/guava/31.1-jre/hash/guava-31.1-jre.jar
		// Group 1: groupId (com.google.guava)
		// Group 2: artifactId (guava)
		// Group 3: version (31.1-jre)
		// Group 4: filename (guava-31.1-jre)
		// Group 5: extension (jar|pom|war)
		gradleRe: regexp.MustCompile(`\.gradle/caches/modules-2/files-2.1/([^/]+)/([^/]+)/([^/]+)/[^/]+/([^/]+)\.(jar|pom|war)$`),
	}
}

func (r *JavaResolver) Name() string {
	return "java"
}

func (r *JavaResolver) Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo) {
	seen := make(map[string]int) // purl -> index in packages

	for _, f := range files {
		p := path.Clean(f.Path)
		var groupId, artifactId, version string

		if m := r.mavenRe.FindStringSubmatch(p); len(m) == 6 {
			// m[1]: group/path, m[2]: artifactId, m[3]: version, m[4]: filename, m[5]: ext
			if m[4] == m[2]+"-"+m[3] {
				groupId = strings.ReplaceAll(m[1], "/", ".")
				artifactId = m[2]
				version = m[3]
			}
		} else if m := r.gradleRe.FindStringSubmatch(p); len(m) == 6 {
			// m[1]: groupId, m[2]: artifactId, m[3]: version, m[4]: filename, m[5]: ext
			if m[4] == m[2]+"-"+m[3] {
				groupId = m[1]
				artifactId = m[2]
				version = m[3]
			}
		}

		if groupId != "" && artifactId != "" && version != "" {
			purl := "pkg:maven/" + groupId + "/" + artifactId + "@" + version
			if idx, ok := seen[purl]; ok {
				// Merge hashes if we see another file for same package (e.g., .pom and .jar)
				if packages[idx].Hashes == nil {
					packages[idx].Hashes = make(map[string]string)
				}
				for k, v := range f.Hashes {
					packages[idx].Hashes[k] = v
				}
			} else {
				seen[purl] = len(packages)
				packages = append(packages, PackageInfo{
					Name:      groupId + ":" + artifactId,
					Version:   version,
					Ecosystem: "maven",
					PURL:      purl,
					Hashes:    f.Hashes,
					FoundBy:   "attestation:java",
				})
			}
			continue
		}

		remainingFiles = append(remainingFiles, f)
	}

	return packages, remainingFiles
}

func (r *JavaResolver) CreateFileFilters(packages []PackageInfo) []PackageFileFilter {
	var filters []PackageFileFilter
	for _, pkg := range packages {
		if pkg.Ecosystem == "maven" {
			parts := strings.SplitN(pkg.Name, ":", 2)
			if len(parts) == 2 {
				filters = append(filters, &javaPackageFilter{
					groupId:    parts[0],
					artifactId: parts[1],
					version:    pkg.Version,
				})
			}
		}
	}
	return filters
}

type javaPackageFilter struct {
	groupId    string
	artifactId string
	version    string
}

func (f *javaPackageFilter) Matches(p string) bool {
	p = strings.ToLower(p)
	groupPath := strings.ReplaceAll(f.groupId, ".", "/")
	
	// Maven match
	if strings.Contains(p, "/.m2/repository/"+groupPath+"/"+f.artifactId+"/"+f.version+"/") {
		return true
	}
	
	// Gradle match
	if strings.Contains(p, "/.gradle/caches/modules-2/files-2.1/"+f.groupId+"/"+f.artifactId+"/"+f.version+"/") {
		return true
	}
	
	return false
}
