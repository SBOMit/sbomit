package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func snapshotGenerateGlobals() func() {
	prevOutputPath := outputPath
	prevOutputFormat := outputFormat
	prevDocumentName := documentName
	prevDocumentVersion := documentVersion
	prevAuthors := append([]string(nil), authors...)
	prevAttestationTypes := append([]string(nil), attestationTypes...)
	prevCatalog := catalog
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
