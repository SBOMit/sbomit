package attestation

import (
	"testing"
)

func TestMavenExtractor_Extract(t *testing.T) {
	e := NewMavenExtractor()
	data := map[string]interface{}{
		"maven": map[string]interface{}{
			"dependencies": []interface{}{
				map[string]interface{}{
					"groupId":    "org.slf4j",
					"artifactId": "slf4j-api",
					"version":    "1.7.32",
					"hashes": map[string]interface{}{
						"sha1": "abc",
					},
				},
			},
		},
	}

	files := e.Extract(data)
	if len(files) != 1 {
		t.Fatalf("Extract() got %v files, want 1", len(files))
	}

	f := files[0]
	expectedPath := "/virtual/.m2/repository/org/slf4j/slf4j-api/1.7.32/slf4j-api-1.7.32.jar"
	if f.Path != expectedPath {
		t.Errorf("Path = %v, want %v", f.Path, expectedPath)
	}

	if f.Hashes["sha1"] != "abc" {
		t.Errorf("Hash[sha1] = %v, want abc", f.Hashes["sha1"])
	}
}
