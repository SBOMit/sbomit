package generator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func TestGenerateFromFileWithOrjsonWitness(t *testing.T) {
	witnessPath := filepath.Join("..", "..", "test", "orjson_witness.json")

	opts := DefaultOptions()
	opts.DocumentName = "orjson-sbom"
	opts.DocumentVersion = "3.11.4"
	opts.Authors = []string{"Test Author"}
	opts.OutputPath = filepath.Join(t.TempDir(), "orjson.spdx.json")

	gen := New(opts)
	doc, err := gen.GenerateFromFile(witnessPath)
	if err != nil {
		t.Fatalf("GenerateFromFile failed on orjson_witness.json: %v", err)
	}

	if doc == nil || doc.NodeList == nil {
		t.Fatal("expected non-nil document and node list")
	}

	if stat, err := os.Stat(opts.OutputPath); err != nil || stat.Size() == 0 {
		t.Errorf("expected non-empty output file at %s, err: %v", opts.OutputPath, err)
	}

	if !strings.HasPrefix(doc.Metadata.Id, "urn:uuid:") {
		t.Errorf("expected UUID urn in doc metadata id, got: %s", doc.Metadata.Id)
	}
	if doc.Metadata.Name != "orjson-sbom" {
		t.Errorf("expected document name 'orjson-sbom', got: %s", doc.Metadata.Name)
	}
	if doc.Metadata.Version != "3.11.4" {
		t.Errorf("expected document version '3.11.4', got: %s", doc.Metadata.Version)
	}
	if len(doc.Metadata.Authors) != 1 || doc.Metadata.Authors[0].Name != "Test Author" {
		t.Errorf("unexpected doc authors: %+v", doc.Metadata.Authors)
	}

	// Verify root application element
	if len(doc.NodeList.RootElements) != 1 {
		t.Fatalf("expected 1 root element, got %d", len(doc.NodeList.RootElements))
	}
	rootID := doc.NodeList.RootElements[0]
	rootNode := doc.NodeList.GetNodeByID(rootID)
	if rootNode == nil {
		t.Fatalf("root node not found for id: %s", rootID)
	}
	if rootNode.Name != "orjson-sbom" {
		t.Errorf("expected root node name 'orjson-sbom', got: %s", rootNode.Name)
	}

	// Verify packages resolved from cargo build
	packagesByPURL := make(map[string]*sbom.Node)
	for _, node := range doc.NodeList.Nodes {
		if node.Type == sbom.Node_PACKAGE && node.Id != rootID {
			packagesByPURL[string(node.Purl())] = node
		}
	}

	expectedCrates := []string{
		"pkg:cargo/serde@1.0.228",
		"pkg:cargo/syn@2.0.108",
		"pkg:cargo/libc@0.2.177",
	}

	for _, crate := range expectedCrates {
		node, ok := packagesByPURL[crate]
		if !ok {
			t.Errorf("expected crate %q resolved in SBOM packages", crate)
			continue
		}
		if node.PrimaryPurpose[0] != sbom.Purpose_LIBRARY {
			t.Errorf("expected library purpose for %s, got: %v", crate, node.PrimaryPurpose)
		}
	}

	// Verify summary report can be produced from the real document
	summary := GenerateSummary(doc)
	if summary.TotalPackages == 0 {
		t.Errorf("expected non-zero total packages, got 0")
	}
	if len(summary.PackagesByEcosystem["cargo"]) == 0 {
		t.Errorf("expected cargo packages in summary breakdown")
	}
}

func TestGenerateFromFileNotFound(t *testing.T) {
	gen := New(DefaultOptions())
	_, err := gen.GenerateFromFile("/path/does/not/exist.json")
	if err == nil {
		t.Fatal("expected error for non-existent witness file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse attestation file") {
		t.Fatalf("expected 'failed to parse attestation file' in error, got: %v", err)
	}
}
