package generator

import (
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sbomit/sbomit/pkg/resolver"
)

func TestCreateDocumentNodeStructureAndRelationships(t *testing.T) {
	opts := &Options{
		DocumentName:    "my-app",
		DocumentVersion: "1.2.0",
		Authors:         []string{"Alice", "Bob"},
	}
	gen := New(opts)

	result := resolver.ResolverResult{
		Packages: []resolver.PackageInfo{
			{
				Name:      "requests",
				Version:   "2.31.0",
				Ecosystem: "pypi",
				PURL:      "pkg:pypi/requests@2.31.0",
				Licenses:  []string{"Apache-2.0"},
				Hashes: map[string]string{
					"sha256": "abc123def456",
					"sha1":   "1234567890abcdef",
				},
			},
		},
		Files: []resolver.FileInfo{
			{
				Path: "src/main.py",
				Hashes: map[string]string{
					"sha256": "filehash123",
				},
			},
		},
	}

	doc := gen.createDocument(result)

	// Validate metadata
	if !strings.HasPrefix(doc.Metadata.Id, "urn:uuid:") {
		t.Errorf("expected urn:uuid prefix in metadata ID, got: %s", doc.Metadata.Id)
	}
	if doc.Metadata.Name != "my-app" {
		t.Errorf("expected doc name 'my-app', got: %s", doc.Metadata.Name)
	}
	if doc.Metadata.Version != "1.2.0" {
		t.Errorf("expected doc version '1.2.0', got: %s", doc.Metadata.Version)
	}
	if len(doc.Metadata.Authors) != 2 {
		t.Fatalf("expected 2 authors, got: %d", len(doc.Metadata.Authors))
	}
	if len(doc.Metadata.Tools) == 0 || doc.Metadata.Tools[0].Name != "sbomit" {
		t.Errorf("expected sbomit in metadata tools, got: %+v", doc.Metadata.Tools)
	}

	// Validate Root application node
	if len(doc.NodeList.RootElements) != 1 {
		t.Fatalf("expected 1 root element, got %d", len(doc.NodeList.RootElements))
	}
	rootID := doc.NodeList.RootElements[0]
	rootNode := doc.NodeList.GetNodeByID(rootID)
	if rootNode == nil {
		t.Fatalf("root node not found for id: %s", rootID)
	}
	if len(rootNode.PrimaryPurpose) == 0 || rootNode.PrimaryPurpose[0] != sbom.Purpose_APPLICATION {
		t.Errorf("expected root node purpose APPLICATION, got: %v", rootNode.PrimaryPurpose)
	}

	// Validate Package node
	pkgNode := doc.NodeList.GetNodeByID("pkg:pypi/requests@2.31.0")
	if pkgNode == nil {
		t.Fatalf("expected package node for requests, got nil")
	}
	if pkgNode.Type != sbom.Node_PACKAGE {
		t.Errorf("expected Node_PACKAGE type, got: %v", pkgNode.Type)
	}
	if len(pkgNode.PrimaryPurpose) == 0 || pkgNode.PrimaryPurpose[0] != sbom.Purpose_LIBRARY {
		t.Errorf("expected package purpose LIBRARY, got: %v", pkgNode.PrimaryPurpose)
	}
	if len(pkgNode.Licenses) != 1 || pkgNode.Licenses[0] != "Apache-2.0" {
		t.Errorf("unexpected package licenses: %v", pkgNode.Licenses)
	}
	if pkgNode.Hashes[int32(sbom.HashAlgorithm_SHA256)] != "abc123def456" {
		t.Errorf("missing or incorrect sha256 hash on package node")
	}

	// Validate File node
	expectedFileID := "File-" + sanitizeID("src/main.py")
	fileNode := doc.NodeList.GetNodeByID(expectedFileID)
	if fileNode == nil {
		t.Fatalf("expected file node %s, got nil", expectedFileID)
	}
	if fileNode.Type != sbom.Node_FILE {
		t.Errorf("expected Node_FILE type, got: %v", fileNode.Type)
	}
	if fileNode.Hashes[int32(sbom.HashAlgorithm_SHA256)] != "filehash123" {
		t.Errorf("missing or incorrect sha256 hash on file node")
	}

	// Validate Edges: app contains package and file
	containsTarget := func(fromID, toID string) bool {
		for _, edge := range doc.NodeList.Edges {
			if edge.From == fromID && edge.Type == sbom.Edge_contains {
				for _, to := range edge.To {
					if to == toID {
						return true
					}
				}
			}
		}
		return false
	}

	if !containsTarget(rootID, pkgNode.Id) {
		t.Errorf("expected root application node to contain package %s", pkgNode.Id)
	}
	if !containsTarget(rootID, fileNode.Id) {
		t.Errorf("expected root application node to contain file %s", fileNode.Id)
	}
}

func TestApplyMetadataDefaultsAndOverrides(t *testing.T) {
	opts := &Options{
		DocumentName:    "fallback-name",
		DocumentVersion: "1.0.0",
		Authors:         []string{"Maintainer"},
	}
	gen := New(opts)

	// Document with nil Metadata
	docWithNilMeta := &sbom.Document{}
	gen.applyMetadata(docWithNilMeta)
	if docWithNilMeta.Metadata == nil {
		t.Fatal("expected metadata initialized from nil")
	}
	if docWithNilMeta.Metadata.Name != "fallback-name" {
		t.Errorf("expected fallback name applied, got: %s", docWithNilMeta.Metadata.Name)
	}
	if docWithNilMeta.Metadata.Version != "1.0.0" {
		t.Errorf("expected fallback version applied, got: %s", docWithNilMeta.Metadata.Version)
	}

	// Document with pre-existing Name and Version should preserve them
	docWithExistingMeta := &sbom.Document{
		Metadata: &sbom.Metadata{
			Name:    "existing-name",
			Version: "2.0.0",
		},
	}
	gen.applyMetadata(docWithExistingMeta)
	if docWithExistingMeta.Metadata.Name != "existing-name" {
		t.Errorf("expected pre-existing name preserved, got: %s", docWithExistingMeta.Metadata.Name)
	}
	if docWithExistingMeta.Metadata.Version != "2.0.0" {
		t.Errorf("expected pre-existing version preserved, got: %s", docWithExistingMeta.Metadata.Version)
	}
}

func TestCreatePackageNodeWithUnsupportedHashAlgorithm(t *testing.T) {
	gen := New(DefaultOptions())

	pkg := resolver.PackageInfo{
		Name:      "test-pkg",
		Version:   "1.0.0",
		Ecosystem: "generic",
		PURL:      "pkg:generic/test-pkg@1.0.0",
		Hashes: map[string]string{
			"unsupported_hash_algo": "hash_val",
			"sha256":                "valid_hash",
		},
	}

	node := gen.createPackageNode(pkg)
	if _, hasUnknown := node.Hashes[int32(sbom.HashAlgorithm_UNKNOWN)]; hasUnknown {
		t.Errorf("expected unknown hash algorithm to be omitted from node hashes")
	}
	if node.Hashes[int32(sbom.HashAlgorithm_SHA256)] != "valid_hash" {
		t.Errorf("expected valid sha256 preserved on node hashes")
	}
}
