package generator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func TestGenerateSummaryCountsPackagesFilesAndEcosystems(t *testing.T) {
	doc := &sbom.Document{
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{
					Id:   "pkg-1",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/react@18.2.0",
					},
				},
				{
					Id:   "pkg-2",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/github.com/spf13/cobra@v1.8.1",
					},
				},
				{
					Id:   "pkg-3",
					Type: sbom.Node_PACKAGE,
				},
				{
					Id:   "file-1",
					Type: sbom.Node_FILE,
				},
			},
		},
	}

	summary := GenerateSummary(doc)

	if summary.TotalPackages != 3 {
		t.Fatalf("expected 3 total packages, got %d", summary.TotalPackages)
	}
	if summary.TotalFiles != 1 {
		t.Fatalf("expected 1 total file, got %d", summary.TotalFiles)
	}
	if got := len(summary.PackagesByEcosystem["npm"]); got != 1 {
		t.Fatalf("expected 1 npm package, got %d", got)
	}
	if got := len(summary.PackagesByEcosystem["golang"]); got != 1 {
		t.Fatalf("expected 1 golang package, got %d", got)
	}
	if got := len(summary.PackagesByEcosystem["unclassified"]); got != 1 {
		t.Fatalf("expected 1 unclassified package, got %d", got)
	}
}

func TestGenerateSummarySkipsRootNode(t *testing.T) {
	rootID := "document-root"
	doc := &sbom.Document{
		NodeList: &sbom.NodeList{
			RootElements: []string{rootID},
			Nodes: []*sbom.Node{
				{
					Id: rootID,
				},
				{
					Id:   "pkg-1",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/lodash@4.17.21",
					},
				},
			},
		},
	}

	summary := GenerateSummary(doc)

	if summary.TotalPackages != 1 {
		t.Fatalf("expected 1 package (root node must be skipped), got %d", summary.TotalPackages)
	}
	if got := len(summary.PackagesByEcosystem["unclassified"]); got != 0 {
		t.Fatalf("expected 0 unclassified packages (root node must be skipped), got %d", got)
	}
}

func TestGenerateSummaryHandlesInvalidPURLsAsUnclassified(t *testing.T) {
	doc := &sbom.Document{
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{
					Id:   "invalid-purl",
					Type: sbom.Node_PACKAGE,
					Identifiers: map[int32]string{
						int32(sbom.SoftwareIdentifierType_PURL): "not-a-purl",
					},
				},
			},
		},
	}

	summary := GenerateSummary(doc)

	if got := len(summary.PackagesByEcosystem["unclassified"]); got != 1 {
		t.Fatalf("expected invalid purl package to be unclassified, got %#v", summary.PackagesByEcosystem)
	}
	if got := summary.PackagesByEcosystem["unclassified"][0]; got != "not-a-purl" {
		t.Fatalf("expected invalid purl to be kept in detail output, got %q", got)
	}
}

func TestWriteSummaryDetailedOutput(t *testing.T) {
	summary := Summary{
		TotalPackages: 3,
		TotalFiles:    1,
		PackagesByEcosystem: map[string][]string{
			"zeta":  {"pkg:zeta/two@2.0.0", "pkg:zeta/one@1.0.0"},
			"alpha": {"pkg:alpha/pkg@1.0.0"},
		},
	}

	var buf bytes.Buffer
	WriteSummary(&buf, summary, true)
	output := buf.String()

	// Each ecosystem section must appear.
	if !strings.Contains(output, "alpha: 1") {
		t.Fatalf("expected 'alpha: 1' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "zeta: 2") {
		t.Fatalf("expected 'zeta: 2' in output, got:\n%s", output)
	}

	// Per-package items within an ecosystem must be sorted alphabetically.
	oneIdx := strings.Index(output, "    - pkg:zeta/one@1.0.0")
	twoIdx := strings.Index(output, "    - pkg:zeta/two@2.0.0")
	if oneIdx == -1 || twoIdx == -1 || oneIdx > twoIdx {
		t.Fatalf("expected detailed package listings to be sorted alphabetically, got:\n%s", output)
	}
}
