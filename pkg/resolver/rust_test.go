package resolver

import (
	"reflect"
	"testing"
)

func TestNormalizeRustCrateName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already normalized",
			input:    "serde",
			expected: "serde",
		},
		{
			name:     "uppercase",
			input:    "Serde",
			expected: "serde",
		},
		{
			name:     "hyphens preserved",
			input:    "pyo3-build-config",
			expected: "pyo3-build-config",
		},
		{
			name:     "underscores preserved",
			input:    "serde_derive",
			expected: "serde_derive",
		},
		{
			name:     "whitespace trimmed",
			input:    "  ring  ",
			expected: "ring",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeRustCrateName(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeRustCrateName(%q) = %q; want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRustResolver_Resolve(t *testing.T) {
	r := NewRustResolver()

	// registry hash from the real orjson witness attestation
	const registryHash = "index.crates.io-1949cf8c6b5b557f"

	tests := []struct {
		name            string
		files           []FileInfo
		expectPackages  []PackageInfo
		expectRemaining int
	}{
		{
			name: "resolves crate from registry src path",
			files: []FileInfo{
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/serde-1.0.228/src/lib.rs"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.228",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.228",
					FoundBy:   "attestation:rust",
				},
			},
			expectRemaining: 1,
		},
		{
			name: "resolves compound hyphenated crate name",
			files: []FileInfo{
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/pyo3-build-config-0.27.1/src/impl_.rs"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "pyo3-build-config",
					Version:   "0.27.1",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/pyo3-build-config@0.27.1",
					FoundBy:   "attestation:rust",
				},
			},
			expectRemaining: 1,
		},
		{
			name: "resolves crate name with underscores",
			files: []FileInfo{
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/serde_derive-1.0.228/src/lib.rs"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "serde_derive",
					Version:   "1.0.228",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde_derive@1.0.228",
					FoundBy:   "attestation:rust",
				},
			},
			expectRemaining: 1,
		},
		{
			name: "deduplicates multiple files from the same crate",
			files: []FileInfo{
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/zerocopy-0.8.27/src/lib.rs"},
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/zerocopy-0.8.27/src/byte_slice.rs"},
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/zerocopy-0.8.27/src/byteorder.rs"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "zerocopy",
					Version:   "0.8.27",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/zerocopy@0.8.27",
					FoundBy:   "attestation:rust",
				},
			},
			expectRemaining: 3,
		},
		{
			name: "resolves .crate file in registry cache",
			files: []FileInfo{
				{Path: "/usr/local/cargo/registry/cache/" + registryHash + "/serde-1.0.228.crate"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.228",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.228",
					FoundBy:   "attestation:rust",
				},
			},
			expectRemaining: 1,
		},
		{
			name: "silently ignores target directory paths",
			files: []FileInfo{
				{Path: "/root/orjson/target/release/deps/libpyo3_build_config-d08df80abd98ca31.rlib"},
			},
			expectPackages:  nil,
			expectRemaining: 0,
		},
		{
			name: "passes non-rust paths to remaining files",
			files: []FileInfo{
				{Path: "/usr/lib/python3/site-packages/requests-2.28.0/requests/__init__.py"},
				{Path: "/usr/bin/pip"},
			},
			expectPackages:  nil,
			expectRemaining: 2,
		},
		{
			name: "resolves multiple distinct crates",
			files: []FileInfo{
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/serde-1.0.228/src/lib.rs"},
				{Path: "/usr/local/cargo/registry/src/" + registryHash + "/proc-macro2-1.0.103/src/lib.rs"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.228",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.228",
					FoundBy:   "attestation:rust",
				},
				{
					Name:      "proc-macro2",
					Version:   "1.0.103",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/proc-macro2@1.0.103",
					FoundBy:   "attestation:rust",
				},
			},
			expectRemaining: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages, remaining := r.Resolve(tt.files)

			if len(packages) != len(tt.expectPackages) {
				t.Fatalf("expected %d packages, got %d: %+v", len(tt.expectPackages), len(packages), packages)
			}

			// compare by PURL to avoid map-iteration ordering flakiness
			byPURL := make(map[string]PackageInfo, len(packages))
			for _, pkg := range packages {
				pkg.Hashes = nil
				byPURL[pkg.PURL] = pkg
			}
			for _, want := range tt.expectPackages {
				got, ok := byPURL[want.PURL]
				if !ok {
					t.Errorf("expected package %q not found in results", want.PURL)
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("package %q mismatch.\nGot:  %+v\nWant: %+v", want.PURL, got, want)
				}
			}

			if len(remaining) != tt.expectRemaining {
				t.Errorf("expected %d remaining files, got %d", tt.expectRemaining, len(remaining))
			}
		})
	}
}
