package generator

import (
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

func TestGenerateFromAttestationsCanUseCatalogFile(t *testing.T) {
	tmp := t.TempDir()
	catalogPath := tmp + "/catalog.spdx.json"
	outPath := tmp + "/out.spdx.json"

	catalogDoc := sbom.NewDocument()
	catalogDoc.Metadata.Id = "urn:uuid:test-catalog"
	catalogDoc.Metadata.Name = "catalog"
	catalogNode := &sbom.Node{
		Id:      "pkg:generic/catalog-package@1.0.0",
		Type:    sbom.Node_PACKAGE,
		Name:    "catalog-package",
		Version: "1.0.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:generic/catalog-package@1.0.0",
		},
	}
	catalogDoc.NodeList.AddRootNode(catalogNode)

	if err := writer.New().WriteFileWithOptions(catalogDoc, catalogPath, &writer.Options{Format: formats.SPDX23JSON}); err != nil {
		t.Fatalf("write catalog SBOM: %v", err)
	}

	gen := New(&Options{
		DocumentName:     "test",
		DocumentVersion:  "0.0.1",
		AttestationTypes: []string{},
		OutputFormat:     "spdx23",
		OutputPath:       outPath,
		CatalogFile:      catalogPath,
		ProjectDir:       "/does/not/exist",
	})

	if _, err := gen.GenerateFromAttestations(nil); err != nil {
		t.Fatalf("generate with catalog file: %v", err)
	}

	outDoc, err := gen.readCatalogFile(outPath)
	if err != nil {
		t.Fatalf("read output SBOM: %v", err)
	}

	for _, node := range outDoc.NodeList.Nodes {
		if node != nil && node.Id == "pkg:generic/catalog-package@1.0.0" {
			return
		}
	}

	t.Fatal("catalog package was not preserved")
}

func TestMergePreferAttestationTracksAddedPackages(t *testing.T) {
	baseDoc := sbom.NewDocument()
	baseDoc.NodeList.AddRootNode(&sbom.Node{Id: "catalog-root"})
	baseDoc.NodeList.AddNode(testPackageNode("pkg:generic/base@1.0.0"))

	attDoc := sbom.NewDocument()
	attDoc.NodeList.AddRootNode(&sbom.Node{Id: "attestation-root"})
	attDoc.NodeList.AddNode(testPackageNode("pkg:generic/added@1.0.0"))

	summary := New(DefaultOptions()).mergePreferAttestation(baseDoc, attDoc)

	if summary.BasePackages != 1 {
		t.Fatalf("expected 1 base package, got %d", summary.BasePackages)
	}
	if summary.AddedPackages != 1 {
		t.Fatalf("expected 1 added package, got %d", summary.AddedPackages)
	}
	if summary.EnrichedPackages != 0 {
		t.Fatalf("expected 0 enriched packages, got %d", summary.EnrichedPackages)
	}
}

func TestMergePreferAttestationTracksEnrichedPackages(t *testing.T) {
	baseDoc := sbom.NewDocument()
	baseDoc.NodeList.AddNode(testPackageNode("pkg:generic/base@1.0.0"))

	attNode := testPackageNode("pkg:generic/base@1.0.0")
	attNode.Hashes = map[int32]string{
		int32(sbom.HashAlgorithm_SHA256): "abc123",
	}
	attDoc := sbom.NewDocument()
	attDoc.NodeList.AddNode(attNode)

	summary := New(DefaultOptions()).mergePreferAttestation(baseDoc, attDoc)

	if summary.AddedPackages != 0 {
		t.Fatalf("expected 0 added packages, got %d", summary.AddedPackages)
	}
	if summary.EnrichedPackages != 1 {
		t.Fatalf("expected 1 enriched package, got %d", summary.EnrichedPackages)
	}
	if got := baseDoc.NodeList.Nodes[0].Hashes[int32(sbom.HashAlgorithm_SHA256)]; got != "abc123" {
		t.Fatalf("expected hash to be merged into base package, got %q", got)
	}
}

func TestMergePreferAttestationMatchesQualifiedPURLAsEnrichment(t *testing.T) {
	baseDoc := sbom.NewDocument()
	baseDoc.NodeList.AddNode(testPackageNode("pkg:pypi/certifi@2025.11.12"))

	attDoc := sbom.NewDocument()
	attDoc.NodeList.AddNode(testPackageNode("pkg:pypi/certifi@2025.11.12?url=https://files.pythonhosted.org/certifi.whl"))

	summary := New(DefaultOptions()).mergePreferAttestation(baseDoc, attDoc)

	if summary.AddedPackages != 0 {
		t.Fatalf("expected qualified PURL to match existing package, got %d added packages", summary.AddedPackages)
	}
	if summary.EnrichedPackages != 1 {
		t.Fatalf("expected qualified PURL to enrich existing package, got %d", summary.EnrichedPackages)
	}
	if got := countPackageNodes(baseDoc, rootElementSet(baseDoc)); got != 1 {
		t.Fatalf("expected no duplicate package after qualified PURL merge, got %d packages", got)
	}
}

func testPackageNode(purl string) *sbom.Node {
	return &sbom.Node{
		Id:      purl,
		Type:    sbom.Node_PACKAGE,
		Name:    purl,
		Version: "1.0.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): purl,
		},
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my/package@1.0.0", "my-package-at-1.0.0"},
		{"group:artifact:1.0", "group-artifact-1.0"},
		{"path\\with\\backslashes", "path-with-backslashes"},
		{"multiple   spaces", "multiple-spaces"},
		{"---leading-and-trailing---", "leading-and-trailing"},
		{"repeated----hyphens", "repeated-hyphens"},
	}

	for _, tc := range tests {
		actual := sanitizeID(tc.input)
		if actual != tc.expected {
			t.Errorf("sanitizeID(%q): expected %q, got %q", tc.input, tc.expected, actual)
		}
	}
}

func TestMapHashAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected sbom.HashAlgorithm
	}{
		{"sha256", sbom.HashAlgorithm_SHA256},
		{"SHA-256", sbom.HashAlgorithm_SHA256},
		{"sha1", sbom.HashAlgorithm_SHA1},
		{"SHA-1", sbom.HashAlgorithm_SHA1},
		{"sha512", sbom.HashAlgorithm_SHA512},
		{"SHA-512", sbom.HashAlgorithm_SHA512},
		{"sha384", sbom.HashAlgorithm_SHA384},
		{"SHA-384", sbom.HashAlgorithm_SHA384},
		{"md5", sbom.HashAlgorithm_MD5},
		{"MD5", sbom.HashAlgorithm_MD5},
		{"unknown-algo", sbom.HashAlgorithm_UNKNOWN},
	}

	for _, tc := range tests {
		actual := mapHashAlgorithm(tc.input)
		if actual != tc.expected {
			t.Errorf("mapHashAlgorithm(%q): expected %v, got %v", tc.input, tc.expected, actual)
		}
	}
}

func TestWithNetworkQualifiers(t *testing.T) {
	tests := []struct {
		name        string
		purl        string
		downloadURL string
		downloadIP  string
		expected    string
	}{
		{
			name:        "Empty qualifiers return untouched PURL",
			purl:        "pkg:golang/github.com/google/uuid@v1.3.0",
			downloadURL: "",
			downloadIP:  "",
			expected:    "pkg:golang/github.com/google/uuid@v1.3.0",
		},
		{
			name:        "PURL with download URL",
			purl:        "pkg:golang/github.com/google/uuid@v1.3.0",
			downloadURL: "https://proxy.golang.org/uuid.zip",
			downloadIP:  "",
			expected:    "pkg:golang/github.com/google/uuid@v1.3.0?url=https://proxy.golang.org/uuid.zip",
		},
		{
			name:        "PURL with download IP and URL",
			purl:        "pkg:golang/github.com/google/uuid@v1.3.0",
			downloadURL: "https://proxy.golang.org/uuid.zip",
			downloadIP:  "142.250.190.49",
			expected:    "pkg:golang/github.com/google/uuid@v1.3.0?url=https://proxy.golang.org/uuid.zip&ip=142.250.190.49",
		},
		{
			name:        "PURL already containing query params appends with ampersand",
			purl:        "pkg:golang/github.com/google/uuid@v1.3.0?existing=val",
			downloadURL: "https://proxy.golang.org/uuid.zip",
			downloadIP:  "",
			expected:    "pkg:golang/github.com/google/uuid@v1.3.0?existing=val&url=https://proxy.golang.org/uuid.zip",
		},
		{
			name:        "Encodes special characters in URL",
			purl:        "pkg:golang/test@v1.0.0",
			downloadURL: "https://example.com/test?a=1&b=2#frag",
			downloadIP:  "",
			expected:    "pkg:golang/test@v1.0.0?url=https://example.com/test%3Fa%3D1%26b%3D2%23frag",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := withNetworkQualifiers(tc.purl, tc.downloadURL, tc.downloadIP)
			if actual != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, actual)
			}
		})
	}
}
