package attestation

import (
	"fmt"
	"os"

	"github.com/bmatcuk/doublestar/v4"
)

// ValidatePath checks if an attestation path looks suspicious (e.g. logs or git directories).
// It prints a warning but does not enforce exclusion.
func ValidatePath(path string) {
	if matchesPattern(path) {
		fmt.Fprintf(os.Stderr, "WARNING: unexpected file in attestation: %s\n", path)
	}
}

func matchesPattern(path string) bool {
	patterns := []string{
		"**/*.log",
		"**/.git/**",
		".git/**",
	}

	for _, pattern := range patterns {
		if matched, err := doublestar.Match(pattern, path); err == nil && matched {
			return true
		}
	}

	return false
}
