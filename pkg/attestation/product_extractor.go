package attestation

// ProductExtractor extracts files from product attestations
// Product attestations typically contain output/build artifacts and their hashes
type ProductExtractor struct{}

func NewProductExtractor() *ProductExtractor {
	return &ProductExtractor{}
}

func (e *ProductExtractor) Name() string {
	return "product"
}

func (e *ProductExtractor) Extract(data map[string]interface{}) []FileInfo {
	var files []FileInfo

	products, ok := data["products"].(map[string]interface{})
	if !ok {
		products = make(map[string]interface{})
		for k, v := range data {
			if k != "command" && k != "environ" && k != "environment" {
				products[k] = v
			}
		}
		if len(products) == 0 {
			return files
		}
	}

	for path, entry := range products {
		// Entries are {"mime_type": ..., "digest": {...}}.
		var hashData interface{} = entry
		if m, ok := entry.(map[string]interface{}); ok {
			if d, ok := m["digest"]; ok {
				hashData = d
			}
		}

		files = append(files, FileInfo{Path: path, Digests: parseDigests(hashData)})
	}

	return files
}
