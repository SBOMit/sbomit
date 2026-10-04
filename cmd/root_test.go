package cmd

import (
	"testing"
)

func TestRootCmdConfig(t *testing.T) {
	if rootCmd.Use != "sbomit" {
		t.Errorf("Expected rootCmd.Use to be 'sbomit', got '%s'", rootCmd.Use)
	}
	if rootCmd.Short == "" {
		t.Errorf("Expected rootCmd to have a Short description")
	}
}

func TestExecuteIsInvokable(t *testing.T) {
	// Not practically testing much, but this gives code coverage for setup
	// We don't invoke Execute() directly as it can call os.Exit(1),
	// but we can verify the command has subcommands attached.
	if !rootCmd.HasSubCommands() {
		t.Errorf("Expected rootCmd to have subcommands (like 'generate')")
	}
}
