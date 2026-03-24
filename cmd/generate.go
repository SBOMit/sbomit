package cmd

import (
	"fmt"
	"os"
	"strings"

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
	projectDir       string
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
	generateCmd.Flags().StringVarP(&catalog, "catalog", "c", "", "Cataloger to run before processing attestations (supported: syft)")
	generateCmd.Flags().StringVar(&projectDir, "project-dir", "", "Project directory to scan with the cataloger (default: current directory)")
}

func runGenerate(attestationFile string) error {
	if _, err := os.Stat(attestationFile); os.IsNotExist(err) {
		return fmt.Errorf("attestation file not found: %s", attestationFile)
	}

	validFormats := map[string]bool{
		"spdx23": true, "spdx22": true, "cdx14": true, "cdx15": true,
		"spdx-2.3": true, "spdx-2.2": true, "cdx-1.4": true, "cdx-1.5": true,
	}
	if !validFormats[strings.ToLower(outputFormat)] {
		return fmt.Errorf("invalid output format: %s (supported: spdx23, spdx22, cdx14, cdx15)", outputFormat)
	}

	validCatalogs := map[string]bool{
		"": true, "syft": true,
	}
	if !validCatalogs[strings.ToLower(catalog)] {
		return fmt.Errorf("invalid catalog: %s (supported: syft)", catalog)
	}

	opts := &generator.Options{
		DocumentName:     documentName,
		DocumentVersion:  documentVersion,
		Authors:          authors,
		AttestationTypes: attestationTypes,
		OutputFormat:     outputFormat,
		OutputPath:       outputPath,
		Catalog:          catalog,
		ProjectDir:       projectDir,
	}

	gen := generator.New(opts)
	if err := gen.GenerateFromFile(attestationFile); err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}

	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "SBOM written to %s\n", outputPath)
	}

	return nil
}
