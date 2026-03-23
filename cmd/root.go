package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sbomit",
	Short: "Generate SBOMs from witness attestations",
	Long: `sbomit is a tool for generating Software Bill of Materials (SBOMs) 
from witness attestations. It parses attestations, resolves file paths to 
packages (Python, Node.js, etc.), and outputs SBOMs in SPDX or CycloneDX formats.

Examples:
  # Generate an SBOM from a witness attestation file
	sbomit generate attestation.json

  # Generate with specific output format
	sbomit generate attestation.json --format cdx14

  # Generate and write to a file
	sbomit generate attestation.json --output sbom.json`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
