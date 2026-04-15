package resolver

import (
	"testing"
)

func TestJavaResolver_Resolve(t *testing.T) {
	tests := []struct {
		name          string
		files         []FileInfo
		wantPackages  []PackageInfo
		wantRemaining int
	}{
		{
			name: "Maven local path - JAR",
			files: []FileInfo{
				{
					Path:   "/home/user/.m2/repository/org/slf4j/slf4j-api/1.7.32/slf4j-api-1.7.32.jar",
					Hashes: map[string]string{"sha1": "abc"},
				},
			},
			wantPackages: []PackageInfo{
				{
					Name:      "org.slf4j:slf4j-api",
					Version:   "1.7.32",
					Ecosystem: "maven",
					PURL:      "pkg:maven/org.slf4j/slf4j-api@1.7.32",
				},
			},
			wantRemaining: 0,
		},
		{
			name: "Maven local path - POM",
			files: []FileInfo{
				{
					Path:   "/home/user/.m2/repository/org/slf4j/slf4j-api/1.7.32/slf4j-api-1.7.32.pom",
					Hashes: map[string]string{"sha1": "abc"},
				},
			},
			wantPackages: []PackageInfo{
				{
					Name:      "org.slf4j:slf4j-api",
					Version:   "1.7.32",
					Ecosystem: "maven",
					PURL:      "pkg:maven/org.slf4j/slf4j-api@1.7.32",
				},
			},
			wantRemaining: 0,
		},
		{
			name: "Gradle cache path",
			files: []FileInfo{
				{
					Path:   "/home/user/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/31.1-jre/12345/guava-31.1-jre.jar",
					Hashes: map[string]string{"sha256": "def"},
				},
			},
			wantPackages: []PackageInfo{
				{
					Name:      "com.google.guava:guava",
					Version:   "31.1-jre",
					Ecosystem: "maven",
					PURL:      "pkg:maven/com.google.guava/guava@31.1-jre",
				},
			},
			wantRemaining: 0,
		},
		{
			name: "Deduplication and Hash merging",
			files: []FileInfo{
				{
					Path:   "/home/user/.m2/repository/org/slf4j/slf4j-api/1.7.32/slf4j-api-1.7.32.jar",
					Hashes: map[string]string{"sha256": "jar-hash"},
				},
				{
					Path:   "/home/user/.m2/repository/org/slf4j/slf4j-api/1.7.32/slf4j-api-1.7.32.pom",
					Hashes: map[string]string{"sha1": "pom-hash"},
				},
			},
			wantPackages: []PackageInfo{
				{
					Name:      "org.slf4j:slf4j-api",
					Version:   "1.7.32",
					Ecosystem: "maven",
					PURL:      "pkg:maven/org.slf4j/slf4j-api@1.7.32",
					Hashes:    map[string]string{"sha256": "jar-hash", "sha1": "pom-hash"},
				},
			},
			wantRemaining: 0,
		},
		{
			name: "Unrelated file",
			files: []FileInfo{
				{Path: "/home/user/project/README.md"},
			},
			wantPackages:  nil,
			wantRemaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewJavaResolver()
			gotPackages, gotRemaining := r.Resolve(tt.files)

			if len(gotPackages) != len(tt.wantPackages) {
				t.Fatalf("Resolve() got %v packages, want %v", len(gotPackages), len(tt.wantPackages))
			}

			for i, wp := range tt.wantPackages {
				gp := gotPackages[i]
				if gp.PURL != wp.PURL {
					t.Errorf("Package[%d] PURL = %v, want %v", i, gp.PURL, wp.PURL)
				}
				if gp.Name != wp.Name {
					t.Errorf("Package[%d] Name = %v, want %v", i, gp.Name, wp.Name)
				}
				if wp.Hashes != nil {
					for k, v := range wp.Hashes {
						if gp.Hashes[k] != v {
							t.Errorf("Package[%d] Hash[%s] = %v, want %v", i, k, gp.Hashes[k], v)
						}
					}
				}
			}

			if len(gotRemaining) != tt.wantRemaining {
				t.Errorf("Resolve() got %v remaining files, want %v", len(gotRemaining), tt.wantRemaining)
			}
		})
	}
}

func TestJavaPackageFilter_Matches(t *testing.T) {
	tests := []struct {
		name    string
		groupId string
		artifactId string
		version string
		path    string
		want    bool
	}{
		{
			name:    "Match Maven path",
			groupId: "org.slf4j",
			artifactId: "slf4j-api",
			version: "1.7.32",
			path:    "/home/user/.m2/repository/org/slf4j/slf4j-api/1.7.32/slf4j-api-1.7.32.jar",
			want:    true,
		},
		{
			name:    "Match Gradle path",
			groupId: "com.google.guava",
			artifactId: "guava",
			version: "31.1-jre",
			path:    "/root/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/31.1-jre/abc/guava-31.1-jre.jar",
			want:    true,
		},
		{
			name:    "Mismatch version",
			groupId: "org.slf4j",
			artifactId: "slf4j-api",
			version: "1.7.32",
			path:    "/home/user/.m2/repository/org/slf4j/slf4j-api/1.7.33/slf4j-api-1.7.33.jar",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &javaPackageFilter{
				groupId:    tt.groupId,
				artifactId: tt.artifactId,
				version:    tt.version,
			}
			if got := f.Matches(tt.path); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
