package resolver

import (
	"regexp"
	"strings"
)

type FileFilter struct {
	excludePatterns []*regexp.Regexp
	excludePrefixes []string
	excludeSuffixes []string
}

func NewFileFilter() *FileFilter {
	return &FileFilter{
		excludePatterns: []*regexp.Regexp{
			// Python cache
			regexp.MustCompile(`__pycache__`),
			regexp.MustCompile(`\.pyc$`),
			regexp.MustCompile(`\.pyo$`),

			// Node.js cache
			regexp.MustCompile(`/node_modules/\.cache/`),
			regexp.MustCompile(`/\.npm/`),

			// General cache directories
			regexp.MustCompile(`/\.cache/`),

			// Build artifacts
			regexp.MustCompile(`/\.git/`),
			regexp.MustCompile(`/\.svn/`),
			regexp.MustCompile(`/\.hg/`),

			// Temp files
			regexp.MustCompile(`\.tmp$`),
			regexp.MustCompile(`\.temp$`),
			regexp.MustCompile(`~$`),

			// Log files
			regexp.MustCompile(`\.log$`),

			// OS-specific
			regexp.MustCompile(`\.DS_Store$`),
			regexp.MustCompile(`Thumbs\.db$`),

			// IDE/Editor files
			regexp.MustCompile(`/\.idea/`),
			regexp.MustCompile(`/\.vscode/`),
			regexp.MustCompile(`\.swp$`),
			regexp.MustCompile(`\.swo$`),

			// Go compiler/linker intermediates in /tmp
			regexp.MustCompile(`/tmp/go-build`),
			regexp.MustCompile(`/tmp/go-link-`),
			regexp.MustCompile(`/tmp/cgo-`),
			regexp.MustCompile(`/tmp/[^/]+/pkg/linux_amd64/`),

			// pip transient download dirs (packages caught via dist-info already)
			regexp.MustCompile(`/tmp/pip-unpack-`),
			regexp.MustCompile(`/tmp/pip-req-`),

			// Rust compiled build output (not registry/source)
			regexp.MustCompile(`/target/release/`),
			regexp.MustCompile(`/target/debug/`),

			// Go telemetry
			regexp.MustCompile(`/\.config/go/telemetry/`),
		},
		excludePrefixes: []string{
			"/proc/",
			"/sys/",
			"/dev/",
			"/run/",
			"/usr/local/go/",  // Go toolchain stdlib source — not project deps
			"/usr/local/go1.", // versioned Go toolchain e.g. /usr/local/go1.24.4/
		},
		excludeSuffixes: []string{
			".pyc",
			".pyo",
			".tmp",
			".temp",
			".log",
			".swp",
			".swo",
			"~",
		},
	}
}

func (f *FileFilter) ShouldInclude(path string) bool {
	for _, prefix := range f.excludePrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}

	for _, suffix := range f.excludeSuffixes {
		if strings.HasSuffix(path, suffix) {
			return false
		}
	}

	for _, pattern := range f.excludePatterns {
		if pattern.MatchString(path) {
			return false
		}
	}

	return true
}
