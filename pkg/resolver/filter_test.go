package resolver

import (
	"testing"
)

func TestFileFilterShouldInclude(t *testing.T) {
	filter := NewFileFilter()

	tests := []struct {
		path     string
		expected bool
	}{
		// Valid files
		{"src/main.go", true},
		{"src/utils/math.go", true},
		{"README.md", true},

		// Excluded by suffix
		{"app.log", false},
		{"temp_data.tmp", false},
		{"script.pyc", false},

		// Excluded by prefix
		{"/proc/cpuinfo", false},
		{"/dev/null", false},
		{"/usr/local/go/src/fmt/print.go", false},

		// Excluded by pattern
		{"project/.git/config", false},
		{"project/node_modules/.cache/babel-loader/123", false},
		{"/tmp/go-build1234/b001/exe", false},
		{"src/Thumbs.db", false},
		{"project/.vscode/settings.json", false},
		{"project/__pycache__/app.cpython-39.pyc", false},
		{"/tmp/pip-unpack-12345/app", false},
		{"src/target/release/app", false},
	}

	for _, test := range tests {
		actual := filter.ShouldInclude(test.path)
		if actual != test.expected {
			t.Errorf("For path '%s', expected %v, got %v", test.path, test.expected, actual)
		}
	}
}
