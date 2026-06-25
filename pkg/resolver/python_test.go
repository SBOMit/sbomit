package resolver

import (
	"reflect"
	"testing"
)

func TestPythonNormalizePackageName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already normalized",
			input:    "requests",
			expected: "requests",
		},
		{
			name:     "with uppercase",
			input:    "Flask",
			expected: "flask",
		},
		{
			name:     "with underscore",
			input:    "foo_bar",
			expected: "foo-bar",
		},
		{
			name:     "with multiple underscores",
			input:    "foo_bar_baz",
			expected: "foo-bar-baz",
		},
		{
			name:     "with multiple hyphens",
			input:    "foo--bar",
			expected: "foo-bar",
		},
		{
			name:     "complex mixed naming",
			input:    "Some_Weird--Package",
			expected: "some-weird-package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePackageName(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePackageName(%q) = %q; want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPythonResolver_Resolve(t *testing.T) {
	resolver := NewPythonResolver()

	tests := []struct {
		name           string
		files          []FileInfo
		expectPackages []PackageInfo
		expectRemaining int
	}{
		{
			name: "resolves dist-info",
			files: []FileInfo{
				{Path: "/usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA"},
				{Path: "/usr/lib/python3/dist-packages/requests/api.py"}, // Should be left as remaining by Resolve, filtered later
			},
			expectPackages: []PackageInfo{
				{
					Name:      "requests",
					Version:   "2.28.1",
					Ecosystem: "pypi",
					PURL:      "pkg:pypi/requests@2.28.1",
					FoundBy:   "attestation:python",
				},
			},
			expectRemaining: 1, // The api.py file
		},
		{
			name: "resolves egg-info",
			files: []FileInfo{
				{Path: "site-packages/PyYAML-6.0.egg-info/PKG-INFO"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "pyyaml",
					Version:   "6.0",
					Ecosystem: "pypi",
					PURL:      "pkg:pypi/pyyaml@6.0",
					FoundBy:   "attestation:python",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "deduplicates packages",
			files: []FileInfo{
				{Path: "site-packages/flask-2.0.1.dist-info/METADATA"},
				{Path: "site-packages/flask-2.0.1.dist-info/RECORD"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "flask",
					Version:   "2.0.1",
					Ecosystem: "pypi",
					PURL:      "pkg:pypi/flask@2.0.1",
					FoundBy:   "attestation:python",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "ignores non-python paths",
			files: []FileInfo{
				{Path: "/usr/bin/python3"},
				{Path: "/etc/passwd"},
			},
			expectPackages: nil,
			expectRemaining: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages, remaining := resolver.Resolve(tt.files)

			if len(packages) != len(tt.expectPackages) {
				t.Fatalf("expected %d packages, got %d", len(tt.expectPackages), len(packages))
			}

			for i := range packages {
				// Don't check hashes in this basic test
				packages[i].Hashes = nil
				if !reflect.DeepEqual(packages[i], tt.expectPackages[i]) {
					t.Errorf("Package mismatch at index %d.\nGot:  %+v\nWant: %+v", i, packages[i], tt.expectPackages[i])
				}
			}

			if len(remaining) != tt.expectRemaining {
				t.Errorf("expected %d remaining files, got %d", tt.expectRemaining, len(remaining))
			}
		})
	}
}
