package main

import (
	"github.com/sbomit/sbomit/cmd"
	"github.com/sbomit/sbomit/pkg/generator"
)

var Version = "0.0.1"

func main() {
	generator.Version = Version
	cmd.Execute()
}
