package attestation

// Extractor is the interface that all attestation type extractors must implement
type Extractor interface {
	// Name returns the name/type of attestation this extractor handles (e.g., "material", "command-run", "product")
	Name() string

	// Extract takes attestation data and returns file information
	// Returns the extracted files from this attestation type
	Extract(data map[string]interface{}) []FileInfo
}

// Map attestation type -> extractor
type ExtractorChain struct {
	extractors map[string]Extractor
}

func NewExtractorChain() *ExtractorChain {
	chain := &ExtractorChain{
		extractors: make(map[string]Extractor),
	}

	// Register extractors
	chain.RegisterExtractor(NewMaterialExtractor())
	chain.RegisterExtractor(NewCommandRunExtractor())
	chain.RegisterExtractor(NewProductExtractor())
	chain.RegisterExtractor(NewMavenExtractor())

	return chain
}

func (c *ExtractorChain) RegisterExtractor(e Extractor) {
	c.extractors[e.Name()] = e
}

func (c *ExtractorChain) GetExtractor(attestationType string) (Extractor, bool) {
	e, ok := c.extractors[attestationType]
	return e, ok
}

func (c *ExtractorChain) ExtractAll(attestations []TypedAttestation, typeFilter []string) []FileInfo {
	var files []FileInfo

	filterSet := make(map[string]struct{})
	if len(typeFilter) > 0 {
		for _, t := range typeFilter {
			filterSet[t] = struct{}{}
		}
	}

	// Deduplicate files by path
	seenPaths := make(map[string]struct{})

	for _, att := range attestations {
		if len(filterSet) > 0 {
			if _, ok := filterSet[att.Type]; !ok {
				continue
			}
		}

		extractor, ok := c.extractors[att.Type]
		if !ok {
			continue
		}

		extracted := extractor.Extract(att.Data)

		for _, f := range extracted {
			if _, seen := seenPaths[f.Path]; !seen {
				seenPaths[f.Path] = struct{}{}
				files = append(files, f)
			}
		}
	}

	return files
}

// SupportedTypes returns a list of attestation types that have registered extractors
func (c *ExtractorChain) SupportedTypes() []string {
	types := make([]string, 0, len(c.extractors))
	for t := range c.extractors {
		types = append(types, t)
	}
	return types
}
