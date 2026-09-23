package attestation

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Positive cases
		{"Git config", ".git/config", true},
		{"Nested git hooks", "repo/.git/hooks/pre-commit", true},
		{"Git directory itself", ".git", true},
		{"App log", "logs/app.log", true},
		{"Absolute path log", "/var/tmp/debug/output.log", true},

		// Negative cases
		{"Go source", "src/main.go", false},
		{"Markdown reader", "README.md", false},
		{"HTML docs", "docs/index.html", false},
		{"Empty path", "", false},
		{"Subtly spoofed git", "mygit/config", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesPattern(tt.path)
			if result != tt.expected {
				t.Errorf("matchesPattern(%q) = %v; want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	// captureStderr is a helper to intercept os.Stderr output
	captureStderr := func(f func()) string {
		origStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		// Execute function
		f()

		w.Close()
		os.Stderr = origStderr

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		return buf.String()
	}

	t.Run("Suspicious path prints warning", func(t *testing.T) {
		path := ".git/config"
		output := captureStderr(func() {
			ValidatePath(path)
		})

		if !strings.Contains(output, "WARNING") {
			t.Errorf("ValidatePath(%q) expected to print warning, got output: %q", path, output)
		}
	})

	t.Run("Safe path does not print warning", func(t *testing.T) {
		path := "src/main.go"
		output := captureStderr(func() {
			ValidatePath(path)
		})

		if output != "" {
			t.Errorf("ValidatePath(%q) expected no output, got: %q", path, output)
		}
	})
}
