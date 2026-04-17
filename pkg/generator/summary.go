package generator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
)

type Summary struct {
	TotalPackages       int
	TotalFiles          int
	EcosystemCounts     map[string]int
	PackagesByEcosystem map[string][]string
}

func GenerateSummary(doc *sbom.Document) Summary {
	summary := Summary{
		TotalPackages:       0,
		TotalFiles:          0,
		EcosystemCounts:     make(map[string]int),
		PackagesByEcosystem: make(map[string][]string),
	}

	if doc == nil || doc.NodeList == nil {
		return summary
	}

	for _, node := range doc.NodeList.Nodes {
		if node.Type == sbom.Node_PACKAGE {
			summary.TotalPackages++

			purl := string(node.Purl())
			if purl != "" {
				ecosystem := extractEcosystemFromPURL(purl)
				if ecosystem != "" {
					summary.EcosystemCounts[ecosystem]++
					summary.PackagesByEcosystem[ecosystem] = append(summary.PackagesByEcosystem[ecosystem], purl)
				} else {
					summary.EcosystemCounts["unclassified"]++
					summary.PackagesByEcosystem["unclassified"] = append(summary.PackagesByEcosystem["unclassified"], node.Id)
				}
			} else {
				summary.EcosystemCounts["unclassified"]++
				summary.PackagesByEcosystem["unclassified"] = append(summary.PackagesByEcosystem["unclassified"], node.Id)
			}
		} else if node.Type == sbom.Node_FILE {
			summary.TotalFiles++
			summary.EcosystemCounts["file"]++
			summary.PackagesByEcosystem["file"] = append(summary.PackagesByEcosystem["file"], node.Id)
		}
	}

	return summary
}

func extractEcosystemFromPURL(purl string) string {
	// PURL format: pkg:type/namespace/name@version?qualifiers#subpath
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}

	// Remove "pkg:"
	remainder := strings.TrimPrefix(purl, "pkg:")

	// Ecosystem (type) is the part before the first '/'
	parts := strings.SplitN(remainder, "/", 2)
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}

	return ""
}

func PrintSummary(summary Summary, detailed bool) {
	fmt.Println("\nSBOM Summary")
	fmt.Println("------------")
	fmt.Printf("Total Packages: %d\n", summary.TotalPackages)
	if summary.TotalFiles > 0 {
		fmt.Printf("Total Files: %d\n", summary.TotalFiles)
	}

	if len(summary.EcosystemCounts) > 0 {
		fmt.Println("\nEcosystem Breakdown:")

		var ecosystems []string
		for eco := range summary.EcosystemCounts {
			ecosystems = append(ecosystems, eco)
		}
		sort.Strings(ecosystems)

		for _, eco := range ecosystems {
			fmt.Printf("  %s: %d\n", eco, summary.EcosystemCounts[eco])
			if detailed {
				items := append([]string{}, summary.PackagesByEcosystem[eco]...)
				sort.Strings(items)
				for _, item := range items {
					fmt.Printf("    - %s\n", item)
				}
			}
		}
	} else {
		fmt.Println("\nEcosystem Breakdown: None")
	}
}
