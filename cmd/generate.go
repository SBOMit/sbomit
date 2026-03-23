package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/sbomit/sbomit/pkg/generator"
	"github.com/spf13/cobra"
)

var (
	attestationFile  string
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
	Use:   "generate",
	Short: "Generate an SBOM from witness attestations",
	Long: `Generate a Software Bill of Materials (SBOM) from witness attestation files.

This command parses witness attestations, extracts file information from 
material, command-run, and product attestations, resolves files to packages
where possible (supporting Python packages currently), and outputs an SBOM
in the specified format.

Supported output formats:
  - spdx23 (default): SPDX 2.3 JSON format
  - spdx22: SPDX 2.2 JSON format  
  - cdx14: CycloneDX 1.4 JSON format
  - cdx15: CycloneDX 1.5 JSON format

Example:
	sbomit generate --attestation witness-attestation.json --format spdx23 --output sbom.json`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runGenerate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&attestationFile, "attestation", "a", "", "Path to the witness attestation file (required)")
	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")
	generateCmd.Flags().StringVarP(&outputFormat, "format", "f", "spdx23", "Output format: spdx23, spdx22, cdx14, cdx15")
	generateCmd.Flags().StringVarP(&documentName, "name", "n", "sbomit-sbom", "Name for the SBOM document")
	generateCmd.Flags().StringVarP(&documentVersion, "version", "v", "0.0.1", "Version for the SBOM document")
	generateCmd.Flags().StringSliceVar(&authors, "author", []string{}, "Document authors (can be specified multiple times)")
	generateCmd.Flags().StringSliceVar(&attestationTypes, "types", []string{"material", "command-run", "product"}, "Attestation types to process")
	generateCmd.Flags().StringVarP(&catalog, "catalog", "c", "", "Cataloger to run before processing attestations (supported: syft)")
	generateCmd.Flags().StringVar(&projectDir, "project-dir", "", "Project directory to scan with the cataloger (defaults to current directory)")

	generateCmd.MarkFlagRequired("attestation")
}

func runGenerate() error {
	if _, err := os.Stat(attestationFile); os.IsNotExist(err) {
		return fmt.Errorf("attestation file not found: %s", attestationFile)
	}

	validFormats := map[string]bool{
		"spdx23": true, "spdx22": true, "cdx14": true, "cdx15": true,
		"spdx-2.3": true, "spdx-2.2": true, "cdx-1.4": true, "cdx-1.5": true,
	}
	if !validFormats[strings.ToLower(outputFormat)] {
		return fmt.Errorf("invalid output format: %s (valid: spdx23, spdx22, cdx14, cdx15)", outputFormat)
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
