package generator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

type bufferWriteCloser struct {
	*bytes.Buffer
}

func (b *bufferWriteCloser) Close() error {
	return nil
}

func TestGetOutputFormatSPDX3(t *testing.T) {
	tests := []struct {
		input    string
		expected formats.Format
	}{
		{"spdx3", formats.SPDX3JSON},
		{"spdx-3.0", formats.SPDX3JSON},
		{"spdx-3.0.1", formats.SPDX3JSON},
		{"spdx30", formats.SPDX3JSON},
		{"spdx30json", formats.SPDX3JSON},
		{"SPDX3", formats.SPDX3JSON},
		{"SPDX-3.0", formats.SPDX3JSON},
	}

	for _, tt := range tests {
		gen := New(&Options{OutputFormat: tt.input})
		if got := gen.getOutputFormat(); got != tt.expected {
			t.Errorf("getOutputFormat(%q) = %v, expected %v", tt.input, got, tt.expected)
		}
	}
}

func TestWriteOutputSPDX3(t *testing.T) {
	doc := sbom.NewDocument()
	doc.Metadata.Id = "urn:uuid:test-spdx3-doc"
	doc.Metadata.Name = "test-spdx3-app"
	doc.Metadata.Version = "1.0.0"

	appNode := &sbom.Node{
		Id:             "pkg:generic/test-spdx3-app@1.0.0",
		Type:           sbom.Node_PACKAGE,
		Name:           "test-spdx3-app",
		Version:        "1.0.0",
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
	}
	doc.NodeList.AddRootNode(appNode)

	pkgNode := &sbom.Node{
		Id:             "pkg:pypi/requests@2.31.0",
		Type:           sbom.Node_PACKAGE,
		Name:           "requests",
		Version:        "2.31.0",
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:pypi/requests@2.31.0",
		},
	}
	doc.NodeList.AddNode(pkgNode)
	doc.NodeList.RelateNodeAtID(pkgNode, appNode.Id, sbom.Edge_contains)

	var buf bytes.Buffer
	w := writer.New()
	err := w.WriteStreamWithOptions(doc, &bufferWriteCloser{Buffer: &buf}, &writer.Options{Format: formats.SPDX3JSON})
	if err != nil {
		t.Fatalf("failed to write SPDX 3.0 document: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("expected non-empty SPDX 3.0 JSON output")
	}
	if !strings.Contains(output, "@context") || !strings.Contains(output, "spdxId") || !strings.Contains(output, "@graph") {
		t.Fatalf("expected SPDX 3.0 JSON elements in output, got:\n%s", output)
	}
}
