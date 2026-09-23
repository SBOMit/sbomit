package resolver

import (
	"testing"
)

func TestRustResolver_Resolve(t *testing.T) {
	tests := []struct {
		name           string
		files          []FileInfo
		wantPackages   []PackageInfo
		wantRemaining  int
	}{
		{
			name: "Valid Cargo registry path",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/lib.rs"},
			},
			wantPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.130",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.130",
				},
			},
			wantRemaining: 1,
		},
		{
			name: "Cargo cache crate file",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/cache/github.com-1ecc6299db9ec823/tokio-1.28.2.crate"},
			},
			wantPackages: []PackageInfo{
				{
					Name:      "tokio",
					Version:   "1.28.2",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/tokio@1.28.2",
				},
			},
			wantRemaining: 1,
		},
		{
			name: "Multiple crates and ignored files",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/index.crates.io-6f17d22bba15001f/regex-1.8.4/src/lib.rs"},
				{Path: "/home/user/.cargo/registry/src/index.crates.io-6f17d22bba15001f/regex-1.8.4/target/debug/libregex.rlib"},
				{Path: "/home/user/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libc-0.2.147/src/lib.rs"},
			},
			wantPackages: []PackageInfo{
				{Name: "regex", Version: "1.8.4", Ecosystem: "cargo", PURL: "pkg:cargo/regex@1.8.4"},
				{Name: "libc", Version: "0.2.147", Ecosystem: "cargo", PURL: "pkg:cargo/libc@0.2.147"},
			},
			wantRemaining: 2,
		},
		{
			name: "Path with version-like string in directory name but not crate",
			files: []FileInfo{
				{Path: "/home/user/not-a-registry/some-package-1.2.3/src/main.rs"},
			},
			wantPackages:  nil,
			wantRemaining: 1,
		},
		{
			name: "Malformed version string",
			files: []FileInfo{
				{Path: "/usr/local/cargo/registry/src/unrecognized/invalid-pkg/src/lib.rs"},
			},
			wantPackages:  nil,
			wantRemaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRustResolver()
			gotPackages, gotRemaining := r.Resolve(tt.files)

			if len(gotPackages) != len(tt.wantPackages) {
				t.Errorf("Resolve() gotPackages length = %v, want %v", len(gotPackages), len(tt.wantPackages))
				return
			}

			for _, wp := range tt.wantPackages {
				found := false
				for _, gp := range gotPackages {
					if gp.Name == wp.Name && gp.Version == wp.Version && gp.PURL == wp.PURL {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Resolve() did not find expected package %+v", wp)
				}
			}

			if len(gotRemaining) != tt.wantRemaining {
				t.Errorf("Resolve() gotRemaining length = %v, want %v", len(gotRemaining), tt.wantRemaining)
			}
		})
	}
}

func TestRustPackageFilter_Matches(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		version     string
		path        string
		want        bool
	}{
		{
			name:        "Match registry src path",
			packageName: "serde",
			version:     "1.0.130",
			path:        "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/lib.rs",
			want:        true,
		},
		{
			name:        "Match registry cache crate",
			packageName: "tokio",
			version:     "1.28.2",
			path:        "/home/user/.cargo/registry/cache/github.com-1ecc6299db9ec823/tokio-1.28.2.crate",
			want:        true,
		},
		{
			name:        "Match from crates directory",
			packageName: "anyhow",
			version:     "1.0.71",
			path:        "/usr/local/cargo/crates/anyhow-1.0.71/src/lib.rs",
			want:        true,
		},
		{
			name:        "Mismatch version",
			packageName: "serde",
			version:     "1.0.130",
			path:        "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.131/src/lib.rs",
			want:        false,
		},
		{
			name:        "Mismatch package name",
			packageName: "serde",
			version:     "1.0.130",
			path:        "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde_json-1.0.130/src/lib.rs",
			want:        false,
		},
		{
			name:        "Non-registry path",
			packageName: "serde",
			version:     "1.0.130",
			path:        "/home/user/not-a-registry/serde-1.0.130/src/lib.rs",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &rustPackageFilter{
				packageName: tt.packageName,
				version:     tt.version,
			}
			if got := f.Matches(tt.path); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
