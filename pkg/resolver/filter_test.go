package resolver

import (
	"testing"
)

func TestFileFilterShouldIncludeSystemAndTempExclusions(t *testing.T) {
	filter := NewFileFilter()

	excludedPaths := []string{
		// System prefixes
		"/proc/cpuinfo",
		"/sys/devices/system/cpu",
		"/dev/null",
		"/run/lock",
		"/usr/local/go/src/fmt/print.go",
		"/usr/local/go1.24.4/src/runtime/proc.go",

		// Excluded suffixes
		"/app/cached.pyc",
		"/app/binary.tmp",
		"/app/execution.log",
		"/app/.vimrc.swp",
		"/app/backup~",

		// Excluded patterns
		"/app/__pycache__/module.cpython-311.pyc",
		"/app/node_modules/.cache/terser/cache.json",
		"/home/user/.npm/_cacache/content-v2/sha512/abc",
		"/home/user/.cache/pip/wheels/test.whl",
		"/workspace/.git/config",
		"/workspace/.idea/workspace.xml",
		"/workspace/.vscode/settings.json",
		"/workspace/.DS_Store",
		"/tmp/go-build12345/b001/exe/a.out",
		"/tmp/pip-unpack-1234/pkg.whl",
		"/workspace/target/debug/app",
		"/home/user/.config/go/telemetry/local/2026-01-01.json",
	}

	for _, p := range excludedPaths {
		if filter.ShouldInclude(p) {
			t.Errorf("expected %q to be excluded by FileFilter", p)
		}
	}

	includedPaths := []string{
		"/workspace/cmd/main.go",
		"/workspace/pkg/generator/generator.go",
		"/workspace/package.json",
		"/workspace/Cargo.toml",
		"/workspace/pom.xml",
		"/workspace/requirements.txt",
		"/workspace/node_modules/express/index.js",
		"/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
	}

	for _, p := range includedPaths {
		if !filter.ShouldInclude(p) {
			t.Errorf("expected %q to be included by FileFilter", p)
		}
	}
}
