package main

import (
	"github.com/sbomit/sbomit/cmd"
	"github.com/sbomit/sbomit/pkg/generator"
)

// Version is the build-time version string set via ldflags.
var Version = "0.0.1"

func main() {
	if Version != "" {
		generator.Version = Version
	}
	cmd.Execute()
}
