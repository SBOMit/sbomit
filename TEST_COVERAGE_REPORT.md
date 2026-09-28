# SBOMIT Repository Analysis & Test Coverage Report

## 1. Contributing Guidelines
**Status:** ❌ Missing
I have analyzed the repository structure (including the root and `.github/` folder), and **no `CONTRIBUTING.md` or similar contributing guidelines file was found**. You might want to create one to help new contributors understand the project structure and submission process.

---

## 2. Repository Overview
The `sbomit` repository is a Go-based project used for generating Software Bill of Materials (SBOM) and analyzing attestations. 

The main directories are:
*   `cmd/` - Contains CLI commands (e.g., `generate.go`, `root.go`).
*   `pkg/` - Core logic, divided into `attestation/`, `generator/`, and `resolver/` (with a subpackage `network/`).
*   `test/` - Contains sample files for testing (like `orjson_witness.json`, `sample-attestation.json`), rather than actual `.go` test scripts.

---

## 3. Testing Analysis
I have performed a thorough scan of all Go files to analyze the test coverage. The project uses standard Go testing practices (`_test.go` files).

### 📊 Total Tests Found: **14**

### ✅ Where Tests Are Added
Tests are currently implemented in only a few specific components (4 files).

1.  **`cmd/generate_test.go` (3 Tests)**
    *   `TestRunGenerateStdoutAndStderrSeparation`
    *   `TestRunGenerateDetailedSummaryToStderrWithFileOutput`
    *   `TestRunGeneratePrintsEnrichmentSummaryWithCatalogFile`

2.  **`pkg/generator/generator_test.go` (4 Tests)**
    *   `TestGenerateFromAttestationsCanUseCatalogFile`
    *   `TestMergePreferAttestationTracksAddedPackages`
    *   `TestMergePreferAttestationTracksEnrichedPackages`
    *   `TestMergePreferAttestationMatchesQualifiedPURLAsEnrichment`

3.  **`pkg/generator/summary_test.go` (4 Tests)**
    *   `TestGenerateSummaryCountsPackagesFilesAndEcosystems`
    *   `TestGenerateSummarySkipsRootNode`
    *   `TestGenerateSummaryHandlesInvalidPURLsAsUnclassified`
    *   `TestWriteSummaryDetailedOutput`

4.  **`pkg/resolver/go_test.go` (3 Tests)**
    *   `TestGoResolverResolvesModuleCacheDownloadFiles`
    *   `TestGoResolverAggregatesModuleCacheAndSourcePaths`
    *   `TestGoResolverEscapesPURLVersion`

---

### ❌ Where Tests Are Missing
A significant portion of the codebase lacks unit tests. The following components and files are missing tests entirely:

*   **`pkg/attestation/` (0 Tests)**
    *   `commandrun_extractor.go`
    *   `extractor.go`
    *   `material_extractor.go`
    *   `parser.go`
    *   `product_extractor.go`
    *   `types.go`
*   **`pkg/resolver/network/` (0 Tests)**
    *   `go.go`
    *   `javascript.go`
    *   `network.go`
    *   `python.go`
    *   `rust.go`
*   **`pkg/resolver/` (Missing in most languages except Go)**
    *   `filter.go`
    *   `javascript.go`
    *   `maven.go`
    *   `python.go`
    *   `resolver.go`
    *   `rust.go`
*   **Root & Commands (0 Tests)**
    *   `cmd/root.go`
    *   `main.go`

---

## 4. Conclusion & Recommendations
1.  **Add `CONTRIBUTING.md`**: Create guidelines to standardise contributions.
2.  **Expand Test Coverage**: Focus on adding tests for `pkg/attestation/` and the other language resolvers (`python.go`, `javascript.go`, `rust.go`, `maven.go`), as they currently have zero coverage.
3.  **Network Mocking**: `pkg/resolver/network/` relies on external requests. Adding tests here using mocks will make the test suite more robust.
