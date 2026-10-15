package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

func TestRunGenerateStdoutAndStderrSeparation(t *testing.T) {
	restore := snapshotGenerateGlobals()
	defer restore()

	outputPath = ""
	outputFormat = "spdx23"
	documentName = "sbomit-sbom"
	documentVersion = "0.0.1"
	authors = nil
	attestationTypes = []string{"material", "command-run", "product", "network-trace"}
	catalog = ""
	catalogFile = ""
	projectDir = ""
	skipPaths = nil
	summaryFlag = false

	stdout, stderr, err := captureGenerateOutput(t, filepath.Join("..", "test", "sample-attestation.json"))
	if err != nil {
		t.Fatalf("runGenerate returned error: %v", err)
	}

	if !strings.Contains(stdout, "\"spdxVersion\"") {
		t.Fatalf("expected SBOM JSON on stdout, got: %s", stdout)
	}
	if strings.Contains(stdout, "SBOM Summary") {
		t.Fatalf("did not expect summary output on stdout: %s", stdout)
	}
	if !strings.Contains(stderr, "SBOM Summary") {
		t.Fatalf("expected summary output on stderr, got: %s", stderr)
	}
	if !strings.Contains(stderr, "Total Packages:") || !strings.Contains(stderr, "Total Files:") {
		t.Fatalf("expected brief summary counts on stderr, got: %s", stderr)
	}
	if strings.Contains(stderr, "    - pkg:") {
		t.Fatalf("did not expect detailed package listing without --summary: %s", stderr)
	}
	if strings.Contains(stderr, "SBOMit Enrichment Summary") {
		t.Fatalf("did not expect enrichment summary without a base catalog, got: %s", stderr)
	}
}

func TestRunGenerateDetailedSummaryToStderrWithFileOutput(t *testing.T) {
	restore := snapshotGenerateGlobals()
	defer restore()

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "sbom.json")

	outputPath = target
	outputFormat = "spdx23"
	documentName = "sbomit-sbom"
	documentVersion = "0.0.1"
	authors = nil
	attestationTypes = []string{"material", "command-run", "product", "network-trace"}
	catalog = ""
	catalogFile = ""
	projectDir = ""
	skipPaths = nil
	summaryFlag = true

	stdout, stderr, err := captureGenerateOutput(t, filepath.Join("..", "test", "sample-attestation.json"))
	if err != nil {
		t.Fatalf("runGenerate returned error: %v", err)
	}

	if stdout != "" {
		t.Fatalf("expected no stdout when writing SBOM to file, got: %s", stdout)
	}
	if !strings.Contains(stderr, "SBOM Summary") {
		t.Fatalf("expected summary output on stderr, got: %s", stderr)
	}
	if !strings.Contains(stderr, "    - pkg:") {
		t.Fatalf("expected detailed package listing on stderr, got: %s", stderr)
	}
	if !strings.Contains(stderr, "SBOM written to "+target) {
		t.Fatalf("expected file output message on stderr, got: %s", stderr)
	}

	written, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read generated SBOM file: %v", err)
	}
	if !bytes.Contains(written, []byte("\"spdxVersion\"")) {
		t.Fatalf("expected SBOM JSON in output file, got: %s", string(written))
	}
}

func TestRunGeneratePrintsEnrichmentSummaryWithCatalogFile(t *testing.T) {
	restore := snapshotGenerateGlobals()
	defer restore()

	tmpDir := t.TempDir()
	catalogPath := filepath.Join(tmpDir, "catalog.spdx.json")
	target := filepath.Join(tmpDir, "sbom.json")
	writeTestCatalog(t, catalogPath)

	outputPath = target
	outputFormat = "spdx23"
	documentName = "sbomit-sbom"
	documentVersion = "0.0.1"
	authors = nil
	attestationTypes = []string{"material", "command-run", "product", "network-trace"}
	catalog = ""
	catalogFile = catalogPath
	projectDir = ""
	skipPaths = nil
	summaryFlag = false

	stdout, stderr, err := captureGenerateOutput(t, filepath.Join("..", "test", "sample-attestation.json"))
	if err != nil {
		t.Fatalf("runGenerate returned error: %v", err)
	}

	if stdout != "" {
		t.Fatalf("expected no stdout when writing SBOM to file, got: %s", stdout)
	}
	if !strings.Contains(stderr, "SBOMit Enrichment Summary") {
		t.Fatalf("expected enrichment summary on stderr, got: %s", stderr)
	}
	if !strings.Contains(stderr, "Base Packages: 1") {
		t.Fatalf("expected base package count in enrichment summary, got: %s", stderr)
	}
	if !strings.Contains(stderr, "SBOM Summary") {
		t.Fatalf("expected existing SBOM summary to remain on stderr, got: %s", stderr)
	}
}

func TestRunGenerateValidationErrors(t *testing.T) {
	restore := snapshotGenerateGlobals()
	defer restore()

	validAttestation := filepath.Join("..", "test", "sample-attestation.json")

	t.Run("Non-existent attestation file", func(t *testing.T) {
		err := runGenerate("non-existent-attestation-file.json")
		if err == nil || !strings.Contains(err.Error(), "attestation file not found") {
			t.Fatalf("expected 'attestation file not found' error, got: %v", err)
		}
	})

	t.Run("Invalid output format", func(t *testing.T) {
		outputFormat = "invalid-format"
		err := runGenerate(validAttestation)
		if err == nil || !strings.Contains(err.Error(), "invalid output format") {
			t.Fatalf("expected 'invalid output format' error, got: %v", err)
		}
	})

	t.Run("Invalid catalog tool", func(t *testing.T) {
		outputFormat = "spdx23"
		catalog = "unsupported-cataloger"
		err := runGenerate(validAttestation)
		if err == nil || !strings.Contains(err.Error(), "invalid catalog") {
			t.Fatalf("expected 'invalid catalog' error, got: %v", err)
		}
	})

	t.Run("Conflicting catalog and catalog-file flags", func(t *testing.T) {
		outputFormat = "spdx23"
		catalog = "syft"
		catalogFile = "some-catalog.json"
		err := runGenerate(validAttestation)
		if err == nil || !strings.Contains(err.Error(), "--catalog and --catalog-file cannot be used together") {
			t.Fatalf("expected conflicting catalog error, got: %v", err)
		}
	})

	t.Run("Non-existent catalog file", func(t *testing.T) {
		outputFormat = "spdx23"
		catalog = ""
		catalogFile = "non-existent-catalog.json"
		err := runGenerate(validAttestation)
		if err == nil || !strings.Contains(err.Error(), "catalog file not found") {
			t.Fatalf("expected 'catalog file not found' error, got: %v", err)
		}
	})
}

func TestRunGenerateSupportedFormatsIntegration(t *testing.T) {
	restore := snapshotGenerateGlobals()
	defer restore()

	formatsToTest := []struct {
		format   string
		contains string
	}{
		{"spdx23", "\"spdxVersion\""},
		{"cdx14", "\"bomFormat\""},
		{"cdx15", "\"bomFormat\""},
	}

	for _, tc := range formatsToTest {
		t.Run("Format_"+tc.format, func(t *testing.T) {
			tmpDir := t.TempDir()
			target := filepath.Join(tmpDir, "sbom_"+tc.format+".json")

			outputPath = target
			outputFormat = tc.format
			documentName = "sbomit-test-" + tc.format
			documentVersion = "1.0.0"
			authors = []string{"SBOMit Tester"}
			attestationTypes = []string{"material", "command-run", "product"}
			catalog = ""
			catalogFile = ""
			projectDir = ""
			skipPaths = nil
			summaryFlag = false

			_, _, err := captureGenerateOutput(t, filepath.Join("..", "test", "sample-attestation.json"))
			if err != nil {
				t.Fatalf("runGenerate failed for format %s: %v", tc.format, err)
			}

			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("failed to read output SBOM: %v", err)
			}

			if !strings.Contains(string(data), tc.contains) {
				t.Fatalf("expected output file to contain %q for format %s", tc.contains, tc.format)
			}
		})
	}
}

func TestRunGenerateWithOrjsonWitnessFixture(t *testing.T) {
	restore := snapshotGenerateGlobals()
	defer restore()

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "orjson-sbom.spdx.json")

	outputPath = target
	outputFormat = "spdx23"
	documentName = "orjson-test"
	documentVersion = "1.0.0"
	authors = []string{"Tester"}
	attestationTypes = []string{"material", "command-run", "product"}
	catalog = ""
	catalogFile = ""
	projectDir = ""
	skipPaths = nil
	summaryFlag = true

	_, stderr, err := captureGenerateOutput(t, filepath.Join("..", "test", "orjson_witness.json"))
	if err != nil {
		t.Fatalf("runGenerate failed on orjson_witness.json: %v", err)
	}

	if !strings.Contains(stderr, "SBOM Summary") {
		t.Fatalf("expected SBOM summary in stderr, got: %s", stderr)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read generated SBOM: %v", err)
	}

	if !strings.Contains(string(data), "\"spdxVersion\": \"SPDX-2.3\"") {
		t.Fatalf("expected SPDX-2.3 version in generated output")
	}
}

func snapshotGenerateGlobals() func() {
	prevOutputPath := outputPath
	prevOutputFormat := outputFormat
	prevDocumentName := documentName
	prevDocumentVersion := documentVersion
	prevAuthors := append([]string(nil), authors...)
	prevAttestationTypes := append([]string(nil), attestationTypes...)
	prevCatalog := catalog
	prevCatalogFile := catalogFile
	prevProjectDir := projectDir
	prevSkipPaths := append([]string(nil), skipPaths...)
	prevSummaryFlag := summaryFlag

	return func() {
		outputPath = prevOutputPath
		outputFormat = prevOutputFormat
		documentName = prevDocumentName
		documentVersion = prevDocumentVersion
		authors = prevAuthors
		attestationTypes = prevAttestationTypes
		catalog = prevCatalog
		catalogFile = prevCatalogFile
		projectDir = prevProjectDir
		skipPaths = prevSkipPaths
		summaryFlag = prevSummaryFlag
	}
}

func captureGenerateOutput(t *testing.T, attestationFile string) (string, string, error) {
	t.Helper()

	origStdout := os.Stdout
	origStderr := os.Stderr

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}

	os.Stdout = stdoutW
	os.Stderr = stderrW

	stdoutCh := make(chan []byte, 1)
	stderrCh := make(chan []byte, 1)
	errCh := make(chan error, 2)

	go func() {
		data, err := readAllPipe(stdoutR)
		if err != nil {
			errCh <- err
			return
		}
		stdoutCh <- data
	}()
	go func() {
		data, err := readAllPipe(stderrR)
		if err != nil {
			errCh <- err
			return
		}
		stderrCh <- data
	}()

	runErr := runGenerate(attestationFile)

	_ = stdoutW.Close()
	_ = stderrW.Close()
	os.Stdout = origStdout
	os.Stderr = origStderr

	stdoutBytes := <-stdoutCh
	stderrBytes := <-stderrCh

	select {
	case err := <-errCh:
		t.Fatalf("failed to capture command output: %v", err)
	default:
	}

	_ = stdoutR.Close()
	_ = stderrR.Close()

	return string(stdoutBytes), string(stderrBytes), runErr
}

func readAllPipe(f *os.File) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(f)
	return buf.Bytes(), err
}

func writeTestCatalog(t *testing.T, path string) {
	t.Helper()

	catalogDoc := sbom.NewDocument()
	catalogDoc.Metadata.Id = "urn:uuid:test-catalog"
	catalogDoc.Metadata.Name = "catalog"
	catalogDoc.NodeList.AddRootNode(&sbom.Node{Id: "catalog-root"})
	catalogDoc.NodeList.AddNode(&sbom.Node{
		Id:      "pkg:generic/catalog-package@1.0.0",
		Type:    sbom.Node_PACKAGE,
		Name:    "catalog-package",
		Version: "1.0.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:generic/catalog-package@1.0.0",
		},
	})

	if err := writer.New().WriteFileWithOptions(catalogDoc, path, &writer.Options{Format: formats.SPDX23JSON}); err != nil {
		t.Fatalf("write catalog SBOM: %v", err)
	}
}
