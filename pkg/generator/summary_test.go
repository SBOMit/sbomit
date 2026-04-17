package generator

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func TestGenerateSummary(t *testing.T) {
	doc := &sbom.Document{
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{
					Id:   "node1",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/react@18.2.0",
					},
				},
				{
					Id:   "node2",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
					},
				},
				{
					Id:   "node3",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/github.com/spf13/cobra@v1.7.0",
					},
				},
				{
					Id:   "node4",
					Type: sbom.Node_PACKAGE,
					// No PURL, should fall to unclassified
				},
				{
					Id:   "node5",
					Type: sbom.Node_FILE,
					// Should not be counted in summary.TotalPackages, but in TotalFiles
				},
			},
		},
	}

	summary := GenerateSummary(doc)

	if summary.TotalPackages != 4 {
		t.Errorf("expected 4 total packages, got %d", summary.TotalPackages)
	}

	if summary.TotalFiles != 1 {
		t.Errorf("expected 1 total file, got %d", summary.TotalFiles)
	}

	if summary.EcosystemCounts["npm"] != 1 {
		t.Errorf("expected 1 npm package, got %d", summary.EcosystemCounts["npm"])
	}

	if summary.EcosystemCounts["golang"] != 2 {
		t.Errorf("expected 2 golang packages, got %d", summary.EcosystemCounts["golang"])
	}

	if summary.EcosystemCounts["unclassified"] != 1 {
		t.Errorf("expected 1 unclassified package, got %d", summary.EcosystemCounts["unclassified"])
	}

	if summary.EcosystemCounts["file"] != 1 {
		t.Errorf("expected 1 file ecosystem, got %d", summary.EcosystemCounts["file"])
	}

	if len(summary.PackagesByEcosystem["npm"]) != 1 || summary.PackagesByEcosystem["npm"][0] != "pkg:npm/react@18.2.0" {
		t.Errorf("expected correct PackagesByEcosystem for npm")
	}

	if len(summary.PackagesByEcosystem["unclassified"]) != 1 || summary.PackagesByEcosystem["unclassified"][0] != "node4" {
		t.Errorf("expected correct PackagesByEcosystem for unclassified")
	}

	if len(summary.PackagesByEcosystem["file"]) != 1 || summary.PackagesByEcosystem["file"][0] != "node5" {
		t.Errorf("expected correct PackagesByEcosystem for file")
	}
}

func TestGenerateSummaryNilDoc(t *testing.T) {
	summary := GenerateSummary(nil)
	if summary.TotalPackages != 0 {
		t.Errorf("expected 0 total packages for nil doc, got %d", summary.TotalPackages)
	}
}

func TestExtractEcosystemFromPURL(t *testing.T) {
	tests := []struct {
		purl     string
		expected string
	}{
		{"pkg:npm/react@18.2.0", "npm"},
		{"pkg:golang/github.com/foo/bar@1.0.0", "golang"},
		{"pkg:rust/crate@1.0", "rust"},
		{"pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1", "maven"},
		{"invalid-purl", ""},
		{"pkg:invalid", "invalid"},
	}

	for _, tt := range tests {
		actual := extractEcosystemFromPURL(tt.purl)
		if actual != tt.expected {
			t.Errorf("expected %s for %s, got %s", tt.expected, tt.purl, actual)
		}
	}
}
