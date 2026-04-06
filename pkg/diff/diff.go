package diff

import (
	"fmt"
	"os"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
)

// normalizePURL removes qualifiers (everything after '?') for comparison
func normalizePURL(purl string) string {
	if purl == "" {
		return ""
	}
	if idx := strings.Index(purl, "?"); idx != -1 {
		return purl[:idx]
	}
	return purl
}

// CompareSBOM compares the base SBOM against the attestation-derived SBOM
// to identify what was added and what properties were updated.
func CompareSBOM(base, enriched *sbom.Document) EnrichmentSummary {
	if base == nil || base.NodeList == nil || enriched == nil || enriched.NodeList == nil {
		return EnrichmentSummary{}
	}

	summary := EnrichmentSummary{}

	// Index base nodes by normalized PURL
	baseIndexByPURL := make(map[string]*sbom.Node)
	totalBasePackages := 0

	for _, node := range base.NodeList.Nodes {
		if node != nil && node.Type == sbom.Node_PACKAGE {
			totalBasePackages++

			purl := string(node.Purl())
			if purl == "" {
				continue
			}

			basePurl := normalizePURL(purl)
			baseIndexByPURL[strings.ToLower(basePurl)] = node
		}
	}

	summary.TotalBase = totalBasePackages

	// Compare enriched nodes against base
	for _, enrichedNode := range enriched.NodeList.Nodes {
		if enrichedNode == nil || enrichedNode.Type != sbom.Node_PACKAGE {
			continue
		}

		purl := string(enrichedNode.Purl())
		if purl == "" {
			continue
		}

		basePurl := normalizePURL(purl)

		baseNode, exists := baseIndexByPURL[strings.ToLower(basePurl)]
		if !exists {
			// New package not found in base
			summary.Added++
		} else {
			// Existing package → check enrichment
			if hasNewEnrichment(baseNode, enrichedNode) {
				summary.Updated++
			}
		}
	}

	return summary
}

// hasNewEnrichment checks if enriched node has additional data compared to base
func hasNewEnrichment(base, enriched *sbom.Node) bool {
	// 1️ Hash comparison
	for algo, hash := range enriched.Hashes {
		if baseHash, exists := base.Hashes[algo]; !exists || baseHash != hash {
			return true
		}
	}

	//  PURL qualifier comparison
	baseP := string(base.Purl())
	enrichedP := string(enriched.Purl())

	baseNorm := normalizePURL(baseP)
	enrichedNorm := normalizePURL(enrichedP)

	// Same base package but enriched has extra qualifiers
	if baseNorm == enrichedNorm && baseP != enrichedP {
		return true
	}

	return false
}

// PrintEnrichmentSummary outputs a formatted summary
func PrintEnrichmentSummary(summary EnrichmentSummary) {
	fmt.Fprintf(os.Stderr, "\nSBOMit Enrichment Summary:\n")
	fmt.Fprintf(os.Stderr, "  • Base Packages: %d\n", summary.TotalBase)
	fmt.Fprintf(os.Stderr, "  •  Added by Attestation: %d\n", summary.Added)
	fmt.Fprintf(os.Stderr, "  •  Enriched Packages (Hashes, URLs, etc): %d\n\n", summary.Updated)
}
