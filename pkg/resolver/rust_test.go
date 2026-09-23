package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRustResolver_Resolve(t *testing.T) {
	resolver := NewRustResolver()

	tests := []struct {
		name              string
		files             []FileInfo
		expectedPackages  []PackageInfo
		expectedRemaining int
	}{
		{
			name: "Valid Cargo registry src path",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/lib.rs"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.130",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.130",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 1,
		},
		{
			name: "Valid Cargo registry cache path (.crate)",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/cache/github.com-1ecc6299db9ec823/log-0.4.14.crate"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "log",
					Version:   "0.4.14",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/log@0.4.14",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 1,
		},
		{
			name: "Crates.io index path",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/index.crates.io-1ecc6299db9ec823/se/rd/serde-1.0.130"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.130",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.130",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 1,
		},
		{
			name: "Invalid path handling - regular source file",
			files: []FileInfo{
				{Path: "/home/user/project/src/main.rs"},
			},
			expectedPackages:  nil,
			expectedRemaining: 1, // Remains as it isn't resolved by rust resolver
		},
		{
			name: "Target directory - ignored path",
			files: []FileInfo{
				{Path: "/home/user/project/target/debug/build/serde-1.0.130/out.rs"},
			},
			expectedPackages:  nil,
			expectedRemaining: 0, // Gets filtered out
		},
		{
			name: "Complex version extraction",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/memchr-2.4.1-alpha.3/src/lib.rs"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "memchr",
					Version:   "2.4.1-alpha.3",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/memchr@2.4.1-alpha.3",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 1,
		},
		{
			name: "Compound hyphenated crate names",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/pyo3-build-config-0.27.1/src/lib.rs"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "pyo3-build-config",
					Version:   "0.27.1",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/pyo3-build-config@0.27.1",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 1,
		},
		{
			name: "Crate names with underscores",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde_derive-1.0.130/src/lib.rs"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "serde_derive",
					Version:   "1.0.130",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde_derive@1.0.130",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 1,
		},
		{
			name: "Deduplication of multiple files from the same crate",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/lib.rs"},
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/de.rs"},
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/ser.rs"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.130",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.130",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 3,
		},
		{
			name: "Multiple distinct crates resolved in one pass",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/lib.rs"},
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/log-0.4.14/src/lib.rs"},
				{Path: "/home/user/project/src/main.rs"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.130",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.130",
					FoundBy:   "attestation:rust",
				},
				{
					Name:      "log",
					Version:   "0.4.14",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/log@0.4.14",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 3,
		},
		{
			name: "Non-rust paths passed through to remaining files",
			files: []FileInfo{
				{Path: "/usr/local/lib/node_modules/npm/package.json"},
			},
			expectedPackages:  nil,
			expectedRemaining: 1,
		},
		{
			name: "Fingerprint directory - ignored path",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/.fingerprint/log-0.4.14"},
			},
			expectedPackages:  nil,
			expectedRemaining: 0,
		},
		{
			name: "Compiled artifacts are filtered if owned by known crate",
			files: []FileInfo{
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/lib.rs"},
				{Path: "/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/libserde.rlib"},
			},
			expectedPackages: []PackageInfo{
				{
					Name:      "serde",
					Version:   "1.0.130",
					Ecosystem: "cargo",
					PURL:      "pkg:cargo/serde@1.0.130",
					FoundBy:   "attestation:rust",
				},
			},
			expectedRemaining: 1, // src/lib.rs is remaining, but the .rlib is filtered out
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages, remainingFiles := resolver.Resolve(tt.files)

			// Map expected for an easy comparison by PURL to avoid order flakiness
			expectedByPURL := make(map[string]PackageInfo)
			for _, pkg := range tt.expectedPackages {
				expectedByPURL[pkg.PURL] = pkg
			}

			// verify packages
			assert.Len(t, packages, len(tt.expectedPackages))
			for _, pkg := range packages {
				expected, exists := expectedByPURL[pkg.PURL]
				assert.True(t, exists, "unexpected package found: %s", pkg.PURL)
				assert.Equal(t, expected.Name, pkg.Name)
				assert.Equal(t, expected.Version, pkg.Version)
				assert.Equal(t, expected.Ecosystem, pkg.Ecosystem)
				assert.Equal(t, expected.PURL, pkg.PURL)
				assert.Equal(t, expected.FoundBy, pkg.FoundBy)
			}

			// verify remaining
			assert.Len(t, remainingFiles, tt.expectedRemaining)
		})
	}
}

func TestRustResolver_CreateFileFilters(t *testing.T) {
	resolver := NewRustResolver()

	packages := []PackageInfo{
		{
			Name:      "serde",
			Version:   "1.0.130",
			Ecosystem: "cargo",
		},
		{
			Name:      "not-cargo",
			Version:   "1.0.0",
			Ecosystem: "npm",
		},
	}

	filters := resolver.CreateFileFilters(packages)

	// Since only rust packages are converted to filters
	assert.Len(t, filters, 1)

	// Test matches
	rustFilter := filters[0]

	// Match src path
	assert.True(t, rustFilter.Matches("/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.130/src/lib.rs"))
	// Match cache path (.crate)
	assert.True(t, rustFilter.Matches("/home/user/.cargo/registry/cache/github.com-1ecc6299db9ec823/serde-1.0.130.crate"))
	// Non-matching version
	assert.False(t, rustFilter.Matches("/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.131/src/lib.rs"))
	// Non-matching package
	assert.False(t, rustFilter.Matches("/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/log-0.4.14/src/lib.rs"))
}

func TestNormalizeRustCrateName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Uppercase letters",
			input:    "SerDe",
			expected: "serde",
		},
		{
			name:     "With spaces",
			input:    "  Log  ",
			expected: "log",
		},
		{
			name:     "Mixed case and spaces",
			input:    "  TokIO  ",
			expected: "tokio",
		},
		{
			name:     "Already normalized",
			input:    "regex",
			expected: "regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizeRustCrateName(tt.input))
		})
	}
}
