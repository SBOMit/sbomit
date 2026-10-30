package resolver

import (
	"path"
	"regexp"
	"strings"
)

type FileFilter struct {
	// keepPatterns override every exclusion, for a file kept inside an
	// excluded directory (Go's regexp cannot express "all but this").
	keepPatterns    []*regexp.Regexp
	excludePatterns []*regexp.Regexp
	excludePrefixes []string
	excludeSuffixes []string
}

func NewFileFilter() *FileFilter {
	return &FileFilter{
		keepPatterns: []*regexp.Regexp{
			// The wheel pip downloaded; the rest of pip-unpack-* is excluded.
			regexp.MustCompile(`/pip-unpack-[^/]*/[^/]+\.whl$`),
		},
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

			// Version control
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

			// pip transient download dirs (staged wheels are kept above).
			regexp.MustCompile(`/pip-unpack-`),
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

// Filter returns the files ShouldInclude accepts, minus conda base
// installations (which need every path to detect).
func (f *FileFilter) Filter(files []FileInfo) []FileInfo {
	bases := condaBaseInstallations(files)

	var kept []FileInfo
	for _, file := range files {
		if !f.ShouldInclude(file.Path) || inCondaBaseInstallation(file.Path, bases) {
			continue
		}
		kept = append(kept, file)
	}
	return kept
}

func (f *FileFilter) ShouldInclude(path string) bool {
	for _, pattern := range f.keepPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}

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

// condaBaseRecordRe matches <prefix>/conda-meta/<name>-<version>-<build>.json.
var condaBaseRecordRe = regexp.MustCompile(`^(.+)/conda-meta/[^/]+\.json$`)

// condaBaseInstallations finds conda installations whose project environment
// the build used. A typical install looks like:
//
//	/home/u/miniforge3/                 base: conda itself, its solver, its Python
//	/home/u/miniforge3/envs/myproject/  the project's environment
//
// When the build used envs/myproject, the base's files belong to conda, not
// to the project, and are dropped.
//
// A directory counts as a base only if the attestation shows both its own
// conda-meta/ records and a path under its envs/. Without envs/ (e.g.
// /opt/conda in a Docker image), the base is the project's environment.
func condaBaseInstallations(files []FileInfo) map[string]struct{} {
	withRecords := map[string]struct{}{}
	withEnvs := map[string]struct{}{}

	for _, f := range files {
		p := path.Clean(f.Path)
		if m := condaBaseRecordRe.FindStringSubmatch(p); m != nil {
			withRecords[m[1]] = struct{}{}
		}
		// Every "/envs/<name>/" is a candidate; install records confirm it.
		for i := strings.Index(p, "/envs/"); i >= 0; {
			rest := p[i+len("/envs/"):]
			if j := strings.Index(rest, "/"); j > 0 {
				withEnvs[p[:i]] = struct{}{}
			}
			next := strings.Index(rest, "/envs/")
			if next < 0 {
				break
			}
			i += len("/envs/") + next
		}
	}

	bases := map[string]struct{}{}
	for prefix := range withEnvs {
		if _, ok := withRecords[prefix]; ok {
			bases[prefix] = struct{}{}
		}
	}
	return bases
}

// inCondaBaseInstallation reports whether a path is in a base installation,
// except envs/ (project environments) and pkgs/ (the default package cache).
func inCondaBaseInstallation(p string, bases map[string]struct{}) bool {
	if len(bases) == 0 {
		return false
	}
	clean := path.Clean(p)
	for base := range bases {
		if !strings.HasPrefix(clean, base+"/") {
			continue
		}
		rest := clean[len(base)+1:]
		if strings.HasPrefix(rest, "envs/") || strings.HasPrefix(rest, "pkgs/") {
			return false
		}
		return true
	}
	return false
}
