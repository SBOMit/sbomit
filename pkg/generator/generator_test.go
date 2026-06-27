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
