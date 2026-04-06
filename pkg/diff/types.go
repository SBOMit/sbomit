package diff

// EnrichmentSummary holds the quantifiable metrics of SBOM enrichment.
type EnrichmentSummary struct {
	TotalBase int
	Added     int
	Updated   int
}
