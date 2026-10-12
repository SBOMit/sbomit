package generator

import (
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sbomit/sbomit/pkg/resolver"
)

func TestMergeNetworkPackagesQualifiersAndNewPackages(t *testing.T) {
	initialResult := resolver.ResolverResult{
		Packages: []resolver.PackageInfo{
			{
				Name:      "certifi",
				Version:   "2023.7.22",
				Ecosystem: "pypi",
				PURL:      "pkg:pypi/certifi@2023.7.22",
			},
		},
	}

	networkPkgs := []resolver.PackageInfo{
		// Should enrich existing package with URL and IP qualifiers
		{
			Name:        "certifi",
			Version:     "2023.7.22",
			PURL:        "pkg:pypi/certifi@2023.7.22",
			DownloadURL: "https://files.pythonhosted.org/certifi.whl?param=1&other=2#frag",
			DownloadIP:  "151.101.128.223",
		},
		// Should append new package
		{
			Name:        "urllib3",
			Version:     "2.0.7",
			Ecosystem:   "pypi",
			PURL:        "pkg:pypi/urllib3@2.0.7",
			DownloadURL: "https://files.pythonhosted.org/urllib3.whl",
			DownloadIP:  "151.101.128.223",
		},
	}

	merged := mergeNetworkPackages(initialResult, networkPkgs)

	if len(merged.Packages) != 2 {
		t.Fatalf("expected 2 packages after merge, got %d", len(merged.Packages))
	}

	enrichedCertifi := merged.Packages[0]
	if !strings.HasPrefix(enrichedCertifi.PURL, "pkg:pypi/certifi@2023.7.22?") {
		t.Errorf("expected qualifiers appended to certifi PURL, got: %s", enrichedCertifi.PURL)
	}

	// Verify RFC 3986 percent encoding of reserved characters (&, =, ?, #)
	if strings.Contains(enrichedCertifi.PURL, "?param=1") || strings.Contains(enrichedCertifi.PURL, "#frag") {
		t.Errorf("expected reserved URL characters in downloadURL to be percent-encoded, got: %s", enrichedCertifi.PURL)
	}
	if !strings.Contains(enrichedCertifi.PURL, "ip=151.101.128.223") {
		t.Errorf("expected ip qualifier in PURL, got: %s", enrichedCertifi.PURL)
	}

	newUrllib3 := merged.Packages[1]
	if newUrllib3.PURL != "pkg:pypi/urllib3@2.0.7" {
		t.Errorf("expected appended package PURL preserved, got: %s", newUrllib3.PURL)
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my/project/name", "my-project-name"},
		{"user@example.com", "user-at-example.com"},
		{"app:v1.0", "app-v1.0"},
		{"spaces in name", "spaces-in-name"},
		{"--leading-and-trailing--", "leading-and-trailing"},
	}

	for _, tt := range tests {
		got := sanitizeID(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeID(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestMapHashAlgorithm(t *testing.T) {
	tests := []struct {
		algo     string
		expected sbom.HashAlgorithm
	}{
		{"sha256", sbom.HashAlgorithm_SHA256},
		{"SHA-256", sbom.HashAlgorithm_SHA256},
		{"sha1", sbom.HashAlgorithm_SHA1},
		{"SHA-1", sbom.HashAlgorithm_SHA1},
		{"sha512", sbom.HashAlgorithm_SHA512},
		{"md5", sbom.HashAlgorithm_MD5},
		{"sha384", sbom.HashAlgorithm_SHA384},
		{"invalid", sbom.HashAlgorithm_UNKNOWN},
	}

	for _, tt := range tests {
		got := mapHashAlgorithm(tt.algo)
		if got != tt.expected {
			t.Errorf("mapHashAlgorithm(%q) = %v, expected %v", tt.algo, got, tt.expected)
		}
	}
}

func TestGetOutputFormat(t *testing.T) {
	tests := []struct {
		format   string
		expected formats.Format
	}{
		{"spdx23", formats.SPDX23JSON},
		{"spdx-2.2", formats.SPDX22JSON},
		{"cdx14", formats.CDX14JSON},
		{"cdx15", formats.CDX15JSON},
		{"unsupported", formats.SPDX23JSON}, // fallback
	}

	for _, tt := range tests {
		gen := New(&Options{OutputFormat: tt.format})
		got := gen.getOutputFormat()
		if got != tt.expected {
			t.Errorf("getOutputFormat for %q = %v, expected %v", tt.format, got, tt.expected)
		}
	}
}

func TestShouldSkip(t *testing.T) {
	gen := New(&Options{
		SkipPaths: []string{"*.tmp", "vendor/*", "test/**"},
	})

	if !gen.shouldSkip("file.tmp") {
		t.Errorf("expected file.tmp to be skipped")
	}
	if !gen.shouldSkip("vendor/lib.go") {
		t.Errorf("expected vendor/lib.go to be skipped")
	}
	if gen.shouldSkip("src/main.go") {
		t.Errorf("did not expect src/main.go to be skipped")
	}
}
