package test

import (
"encoding/json"
"os"
"path/filepath"
"strings"
"testing"

"github.com/sbomit/sbomit/pkg/generator"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"
)

func TestIntegration_SBOMGeneration(t *testing.T) {
// Use existing sample attestation file
attestationFile := "sample-attestation.json"

if _, err := os.Stat(attestationFile); os.IsNotExist(err) {
t.Skipf("Skipping integration test: %s not found", attestationFile)
}

tests := []struct {
name          string
attestFile    string
format        string
types         []string
docName       string
docVersion    string
authors       []string
expectError   bool
errorContains string
validateSBOM  func(t *testing.T, sbomBytes []byte, format string)
}{
{
name:       "Generate SPDX 2.3",
attestFile: attestationFile,
format:     "spdx23",
types:      []string{"material", "command-run", "product", "network-trace"},
docName:    "int-test-spdx23",
docVersion: "1.0.0",
authors:    []string{"Integration Test Runner"},
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err, "Output should be valid JSON")

assert.Equal(t, "SPDX-2.3", out["spdxVersion"])
assert.Equal(t, "int-test-spdx23", out["name"])

packages, ok := out["packages"].([]interface{})
assert.True(t, ok, "SBOM should have packages")
assert.Greater(t, len(packages), 0, "Should extract at least some packages")
},
},
{
name:       "Generate CycloneDX 1.5",
attestFile: attestationFile,
format:     "cdx15",
types:      []string{"material", "command-run", "product", "network-trace"},
docName:    "int-test-cdx15",
docVersion: "2.0.0",
authors:    []string{"Test Author 1", "Test Author 2"},
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err, "Output should be valid JSON")

assert.Equal(t, "1.5", out["specVersion"])
metadata, ok := out["metadata"].(map[string]interface{})
if assert.True(t, ok, "SBOM should have metadata") {
component, ok := metadata["component"].(map[string]interface{})
if assert.True(t, ok, "Metadata should have component") {
assert.Equal(t, "int-test-cdx15", component["name"])
assert.Equal(t, "2.0.0", component["version"])
}
authorsList, ok := metadata["authors"].([]interface{})
if assert.True(t, ok, "Metadata should have authors") {
assert.Len(t, authorsList, 2)
}
}

components, ok := out["components"].([]interface{})
assert.True(t, ok, "SBOM should have components")
assert.Greater(t, len(components), 0, "Should extract at least some components")
},
},
{
name:       "Filter by Attestation Type - material only",
attestFile: attestationFile,
format:     "spdx23",
types:      []string{"material"},
docName:    "int-test-filtered",
docVersion: "1.0.0",
authors:    []string{},
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err)
_, ok := out["packages"].([]interface{})
assert.True(t, ok, "SBOM should have packages")
},
},
{
name:       "Filter by Attestation Type - command-run only",
attestFile: attestationFile,
format:     "spdx23",
types:      []string{"command-run"},
docName:    "int-test-command",
docVersion: "1.0.0",
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err)
// Basic check, might not extract full details without material, but verifies process flows cleanly
_, ok := out["packages"].([]interface{})
assert.True(t, ok, "SBOM should have packages key even if empty or partial")
},
},
{
name:       "Filter by Attestation Type - product only",
attestFile: attestationFile,
format:     "spdx23",
types:      []string{"product"},
docName:    "int-test-product",
docVersion: "1.0.0",
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err)
_, ok := out["packages"].([]interface{})
assert.True(t, ok, "SBOM should have packages")
},
},
{
name:       "Filter by Attestation Type - network-trace only",
attestFile: attestationFile,
format:     "spdx23",
types:      []string{"network-trace"},
docName:    "int-test-network",
docVersion: "1.0.0",
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err)
// Attestation may not have network-trace, so it generates largely blank SBOM, but shouldn't error.
assert.Equal(t, "SPDX-2.3", out["spdxVersion"])
},
},
{
name:       "Empty Attestation Filter",
attestFile: attestationFile,
format:     "spdx23",
types:      []string{}, // No filters, usually defaults or skipped
docName:    "int-test-nofilter",
docVersion: "1.0.0",
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err)
assert.Equal(t, "SPDX-2.3", out["spdxVersion"])
},
},
{
name:       "Generate SPDX 2.2",
attestFile: attestationFile,
format:     "spdx22",
types:      []string{"material"},
docName:    "int-test-spdx22",
docVersion: "1.0.0",
authors:    []string{},
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err)
assert.Equal(t, "SPDX-2.2", out["spdxVersion"])
},
},
{
name:       "Generate CycloneDX 1.4",
attestFile: attestationFile,
format:     "cdx14",
types:      []string{"material"},
docName:    "int-test-cdx14",
docVersion: "1.0.0",
authors:    []string{},
validateSBOM: func(t *testing.T, sbomBytes []byte, format string) {
var out map[string]interface{}
err := json.Unmarshal(sbomBytes, &out)
require.NoError(t, err)
assert.Equal(t, "1.4", out["specVersion"])
},
},
{
name:          "Error - Missing Attestation File",
attestFile:    "nonexistent-attestation-file.json",
format:        "spdx23",
types:         []string{"material"},
expectError:   true,
errorContains: "no such file or directory",
},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
tmpDir := t.TempDir()
outputFile := filepath.Join(tmpDir, "sbom.json")

opts := &generator.Options{
DocumentName:     tt.docName,
DocumentVersion:  tt.docVersion,
Authors:          tt.authors,
AttestationTypes: tt.types,
OutputFormat:     tt.format,
OutputPath:       outputFile,
Catalog:          "",
}

gen := generator.New(opts)
err := gen.GenerateFromFile(tt.attestFile)

// Known protobom limitation handling for spdx22
if tt.format == "spdx22" && err != nil && strings.Contains(err.Error(), "unable to find serializer") {
t.Skip("SPDX 2.2 serialization is currently unsupported by protobom v0.4.2")
return
}

if tt.expectError {
require.Error(t, err, "Expected an error but got none")
if tt.errorContains != "" {
assert.Contains(t, err.Error(), tt.errorContains)
}
return
}

require.NoError(t, err, "GenerateFromFile should not return error")

sbomBytes, err := os.ReadFile(outputFile)
require.NoError(t, err, "Should be able to read output file")
assert.NotEmpty(t, sbomBytes, "Output file should not be empty")

if tt.validateSBOM != nil {
tt.validateSBOM(t, sbomBytes, tt.format)
}
})
}
}

func TestIntegration_InvalidJSON(t *testing.T) {
// Create a dummy corrupted file
tmpDir := t.TempDir()
invalidFile := filepath.Join(tmpDir, "invalid-attestation.json")

// Write malformed JSON
err := os.WriteFile(invalidFile, []byte("{ malformed json"), 0644)
require.NoError(t, err)

opts := &generator.Options{
DocumentName:     "doc",
DocumentVersion:  "1",
AttestationTypes: []string{"material"},
OutputFormat:     "spdx23",
OutputPath:       filepath.Join(tmpDir, "out.json"),
}

gen := generator.New(opts)
err = gen.GenerateFromFile(invalidFile)

require.Error(t, err, "Should error out on invalid JSON file input")
}
