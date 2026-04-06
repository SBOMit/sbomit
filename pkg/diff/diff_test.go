package diff

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func TestCompareSBOM(t *testing.T) {
	// Base document with two packages
	baseDoc := &sbom.Document{
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{
					Id:   "pkg:npm/base-pkg@1.0.0",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/base-pkg@1.0.0",
					},
					Hashes: make(map[int32]string),
				},
				{
					Id:   "pkg:npm/network-pkg@1.0.0",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/network-pkg@1.0.0",
					},
					Hashes: make(map[int32]string),
				},
			},
		},
	}

	// Calculate enriched document with an additional package and two enriched packages
	enrichedDoc := &sbom.Document{
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				// Enriched node (added a hash)
				{
					Id:   "pkg:npm/base-pkg@1.0.0",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/base-pkg@1.0.0",
					},
					Hashes: map[int32]string{
						int32(sbom.HashAlgorithm_SHA256): "deadbeef",
					},
				},
				// Enriched node (added PURL qualifiers from network trace)
				{
					Id:   "pkg:npm/network-pkg@1.0.0",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/network-pkg@1.0.0?url=https://registry.npmjs.org",
					},
					Hashes: make(map[int32]string),
				},
				// Completely unlisted node
				{
					Id:   "pkg:npm/added-pkg@2.0.0",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/added-pkg@2.0.0",
					},
					Hashes: make(map[int32]string),
				},
			},
		},
	}

	summary := CompareSBOM(baseDoc, enrichedDoc)

	if summary.TotalBase != 2 {
		t.Errorf("Expected TotalBase to be 2, got %d", summary.TotalBase)
	}

	if summary.Added != 1 {
		t.Errorf("Expected Added to be 1, got %d", summary.Added)
	}

	if summary.Updated != 2 {
		t.Errorf("Expected Updated to be 2, got %d", summary.Updated)
	}
}

func TestCompareSBOM_Empty(t *testing.T) {
	summary := CompareSBOM(nil, nil)
	if summary.TotalBase != 0 || summary.Added != 0 || summary.Updated != 0 {
		t.Errorf("Expected zeros for nil inputs, got %+v", summary)
	}

	emptyDoc := &sbom.Document{NodeList: &sbom.NodeList{}}
	summary = CompareSBOM(emptyDoc, emptyDoc)
	if summary.TotalBase != 0 || summary.Added != 0 || summary.Updated != 0 {
		t.Errorf("Expected zeros for empty inputs, got %+v", summary)
	}
}
