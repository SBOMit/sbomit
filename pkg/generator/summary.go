package generator

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
)

type Summary struct {
	TotalPackages       int
	TotalFiles          int
	PackagesByEcosystem map[string][]string
}

func GenerateSummary(doc *sbom.Document) Summary {
	summary := Summary{
		PackagesByEcosystem: make(map[string][]string),
	}

	if doc == nil || doc.NodeList == nil {
		return summary
	}

	rootElements := make(map[string]bool, len(doc.NodeList.RootElements))
	for _, id := range doc.NodeList.RootElements {
		rootElements[id] = true
	}

	for _, node := range doc.NodeList.Nodes {
		if rootElements[node.Id] {
			continue
		}
		switch node.Type {
		case sbom.Node_PACKAGE:
			summary.TotalPackages++
			ecosystem, item := summarizePackageNode(node)
			summary.PackagesByEcosystem[ecosystem] = append(summary.PackagesByEcosystem[ecosystem], item)
		case sbom.Node_FILE:
			summary.TotalFiles++
		}
	}

	return summary
}

func summarizePackageNode(node *sbom.Node) (string, string) {
	purl := string(node.Purl())

	// Only catalog-merged (syft/trivy) nodes can lack a PURL.
	if purl == "" {
		name := node.Name
		if name == "" {
			name = "unknown-package"
		}
		return "unclassified", name
	}

	if after, ok := strings.CutPrefix(purl, "pkg:"); ok && after != "" {
		if ecosystem := strings.SplitN(after, "/", 2)[0]; ecosystem != "" {
			return ecosystem, purl
		}
	}
	return "unclassified", purl
}

func WriteSummary(w io.Writer, summary Summary, detailed bool) {
	fmt.Fprintln(w, "SBOM Summary")
	fmt.Fprintln(w, "------------")
	fmt.Fprintf(w, "Total Packages: %d\n", summary.TotalPackages)
	fmt.Fprintf(w, "Total Files: %d\n", summary.TotalFiles)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Ecosystem Breakdown:")

	if len(summary.PackagesByEcosystem) == 0 {
		fmt.Fprintln(w, "  none")
		return
	}

	for ecosystem, pkgs := range summary.PackagesByEcosystem {
		fmt.Fprintf(w, "  %s: %d\n", ecosystem, len(pkgs))
		if !detailed {
			continue
		}

		items := append([]string(nil), pkgs...)
		sort.Strings(items)
		for _, item := range items {
			fmt.Fprintf(w, "    - %s\n", item)
		}
	}
}
