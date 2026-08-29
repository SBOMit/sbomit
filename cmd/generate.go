package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/sbomit/sbomit/pkg/generator"
	"github.com/spf13/cobra"
)

var (
	outputPath       string
	outputFormat     string
	documentName     string
	documentVersion  string
	authors          []string
	attestationTypes []string
	catalog          string
	catalogFile      string
	projectDir       string
	skipPaths        []string
	summaryFlag      bool
)

var generateCmd = &cobra.Command{
	Use:   "generate <attestation-file>",
	Short: "Generate an SBOM from witness attestations",
	Long: `Generate a Software Bill of Materials (SBOM) from witness attestation files.

This command parses witness attestations, extracts file and network information
from material, command-run, product, and network-trace attestations, resolves
files and network connections to packages by ecosystem, and outputs an SBOM in
the specified format.

Supported output formats:
  - spdx23 (default): SPDX 2.3 JSON format
  - spdx22: SPDX 2.2 JSON format  
  - cdx14: CycloneDX 1.4 JSON format
  - cdx15: CycloneDX 1.5 JSON format

Example:
	sbomit generate witness-attestation.json --format spdx23 --output sbom.json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		attestationFile := args[0]
		if err := runGenerate(attestationFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")
	generateCmd.Flags().StringVarP(&outputFormat, "format", "f", "spdx23", "SBOM output format (supported: spdx23, spdx22, cdx14, cdx15)")
	generateCmd.Flags().StringVarP(&documentName, "name", "n", "sbomit-sbom", "Name for the SBOM document")
	generateCmd.Flags().StringVarP(&documentVersion, "version", "v", "0.0.1", "Version for the SBOM document")
	generateCmd.Flags().StringSliceVar(&authors, "author", []string{}, "Document authors (can be specified multiple times)")
	generateCmd.Flags().StringSliceVar(&attestationTypes, "types", []string{"material", "command-run", "product", "network-trace"}, "Attestation types to parse (comma-separated).")
	generateCmd.Flags().StringVarP(&catalog, "catalog", "c", "", "Cataloger to run before processing attestations (supported: syft, trivy)")
	generateCmd.Flags().StringVar(&catalogFile, "catalog-file", "", "Existing SBOM catalog file to merge with attestation-derived packages")
	generateCmd.Flags().StringVar(&projectDir, "project-dir", "", "Project directory to scan with the cataloger (default: current directory)")
	generateCmd.Flags().StringSliceVar(&skipPaths, "skip-path", []string{}, "Exclude paths matching glob pattern")
	generateCmd.Flags().BoolVar(&summaryFlag, "summary", false, "Also print per-package details under each ecosystem (default: only ecosystem counts are shown)")
}

func runGenerate(attestationFile string) error {
	if _, err := os.Stat(attestationFile); os.IsNotExist(err) {
		return fmt.Errorf("attestation file not found: %s", attestationFile)
	}

	opts := &generator.Options{
		DocumentName:     documentName,
		DocumentVersion:  documentVersion,
		Authors:          authors,
		AttestationTypes: attestationTypes,
		OutputFormat:     outputFormat,
		OutputPath:       outputPath,
		Catalog:          catalog,
		CatalogFile:      catalogFile,
		ProjectDir:       projectDir,
		SkipPaths:        skipPaths,
	}

	if err := opts.Validate(); err != nil {
		return err
	}

	// File-existence check stays here: it is a CLI UX concern (fast failure
	// before any processing) rather than pure option validation.
	if catalogFile != "" {
		if _, err := os.Stat(catalogFile); os.IsNotExist(err) {
			return fmt.Errorf("catalog file not found: %s", catalogFile)
		}
	}

	gen := generator.New(opts)
	doc, err := gen.GenerateFromFile(attestationFile)
	if err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}

	// Choose output destination and write the document.
	var out io.Writer
	if outputPath == "" || outputPath == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	if err := gen.Write(out, doc); err != nil {
		return fmt.Errorf("write SBOM: %w", err)
	}

	generator.WriteSummary(os.Stderr, generator.GenerateSummary(doc), summaryFlag)

	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "SBOM written to %s\n", outputPath)
	}

	return nil
}
