package resolver

import (
	"reflect"
	"testing"
)

func TestDecodeGoModulePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "regular path",
			input:    "github.com/stretchr/testify",
			expected: "github.com/stretchr/testify",
		},
		{
			name:     "uppercase encoded",
			input:    "github.com/!sirupsen/logrus",
			expected: "github.com/Sirupsen/logrus",
		},
		{
			name:     "multiple uppercase encoded",
			input:    "github.com/!azure/!a!z!u!r!e",
			expected: "github.com/Azure/AZURE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeGoModulePath(tt.input)
			if result != tt.expected {
				t.Errorf("DecodeGoModulePath(%q) = %q; want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGoResolver_Resolve(t *testing.T) {
	resolver := NewGoResolver()

	tests := []struct {
		name            string
		files           []FileInfo
		expectPackages  []PackageInfo
		expectRemaining int
	}{
		{
			name: "resolves regular go module",
			files: []FileInfo{
				{Path: "/home/user/go/pkg/mod/github.com/google/uuid@v1.3.0/uuid.go"},
				{Path: "/home/user/go/pkg/mod/github.com/google/uuid@v1.3.0/util.go"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "github.com/google/uuid",
					Version:   "v1.3.0",
					Ecosystem: "golang",
					PURL:      "pkg:golang/github.com/google/uuid@v1.3.0",
					FoundBy:   "attestation:go",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves encoded uppercase path",
			files: []FileInfo{
				{Path: "/home/user/go/pkg/mod/github.com/!sirupsen/logrus@v1.8.1/logger.go"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "github.com/Sirupsen/logrus", // Decoded
					Version:   "v1.8.1",
					Ecosystem: "golang",
					PURL:      "pkg:golang/github.com/Sirupsen/logrus@v1.8.1",
					FoundBy:   "attestation:go",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "resolves cache download info",
			files: []FileInfo{
				{Path: "/home/user/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.0.0-20220114195835-da31bd327af9.info"},
			},
			expectPackages: []PackageInfo{
				{
					Name:      "golang.org/x/sys",
					Version:   "v0.0.0-20220114195835-da31bd327af9",
					Ecosystem: "golang",
					PURL:      "pkg:golang/golang.org/x/sys@v0.0.0-20220114195835-da31bd327af9",
					FoundBy:   "attestation:go",
				},
			},
			expectRemaining: 0,
		},
		{
			name: "ignores non-module paths",
			files: []FileInfo{
				{Path: "/usr/local/go/src/fmt/print.go"},
				{Path: "cmd/main.go"},
			},
			expectPackages:  nil,
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
				// Avoid checking hashes array allocation inside deepEqual
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