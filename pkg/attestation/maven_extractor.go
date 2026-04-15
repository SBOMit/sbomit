package attestation

import (
	"fmt"
)

// MavenExtractor extracts Maven dependencies from witness maven attestations
type MavenExtractor struct{}

func NewMavenExtractor() *MavenExtractor {
	return &MavenExtractor{}
}

func (e *MavenExtractor) Name() string {
	return "maven"
}

func (e *MavenExtractor) Extract(data map[string]interface{}) []FileInfo {
	var files []FileInfo

	maven, ok := data["maven"].(map[string]interface{})
	if !ok {
		return nil
	}

	deps, ok := maven["dependencies"].([]interface{})
	if !ok {
		return nil
	}

	for _, d := range deps {
		dep, ok := d.(map[string]interface{})
		if !ok {
			continue
		}

		groupId, _ := dep["groupId"].(string)
		artifactId, _ := dep["artifactId"].(string)
		version, _ := dep["version"].(string)

		if groupId == "" || artifactId == "" || version == "" {
			continue
		}

		// Convert back to structured path so JavaResolver can process it
		// This path is virtual and used for coordinate extraction
		groupPath := ""
		for _, part := range fmt.Sprintf("%s", groupId) {
			if part == '.' {
				groupPath += "/"
			} else {
				groupPath += string(part)
			}
		}
		
		virtualPath := fmt.Sprintf("/virtual/.m2/repository/%s/%s/%s/%s-%s.jar", 
			groupPath, artifactId, version, artifactId, version)

		hashes := make(map[string]string)
		if h, ok := dep["hashes"].(map[string]interface{}); ok {
			for k, v := range h {
				if hashVal, ok := v.(string); ok {
					hashes[k] = hashVal
				}
			}
		}

		files = append(files, FileInfo{
			Path:   virtualPath,
			Hashes: hashes,
		})
	}

	return files
}
