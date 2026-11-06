# Sbomit

Generate Software Bill of Materials (SBOMs) from Witness attestations.

## Overview

`sbomit` parses witness attestation files and generates SBOMs in SPDX or CycloneDX format. It:
- Extracts files from attestation types
- Resolves files to packages using ecosystem-specific resolvers (Python, Go, Rust, etc.)
- Filters out package files already listed as packages
- Supports multiple SBOM output formats

## Installation

```bash
go install github.com/sbomit/sbomit@latest
```

## Usage

```bash
Usage:
  sbomit generate <attestation-file> [flags]

Flags:
      --author strings       Document authors (can be specified multiple times)
  -c, --catalog string       Cataloger to run before processing attestations (supported: syft, trivy)
      --catalog-file string  Existing SBOM catalog file to merge with attestation-derived packages
  -f, --format string        SBOM output format (supported: spdx23, cdx14, cdx15) (default "spdx23")
  -h, --help                 help for generate
      --include-owned-files  Also list the files each package owns (default: only files no package owns)
  -n, --name string          Name for the SBOM document (default "sbomit-sbom")
  -o, --output string        Output file path (default: stdout)
      --project-dir string   Project directory to scan with the cataloger (default: current directory)
      --skip-path strings    Exclude paths matching glob pattern
      --summary              Also print per-package details under each ecosystem
      --types strings        Attestation types to parse (comma-separated). (default [material,command-run,product,network-trace])
  -v, --version string       Version for the SBOM document (default "0.0.1")
```

By default, `sbomit` parses `material`, `command-run`, `product`, and `network-trace` attestations. To restrict parsing on demand:

```bash
sbomit generate attestation.json --types command-run
```

## Syft Catalog Option

Sbomit outputs a flat list of dependencies. If the SBOM metadata syft derives includes dependency structure, using syft first can help preserve more relationship context.

Example:

```bash
sbomit generate attestation.json --catalog syft --project-dir /path/to/project
```

## Catalog File Option

If you already have an SBOM from another cataloger, pass it with `--catalog-file`.
Sbomit will use that file as the base catalog and merge packages resolved from the
Witness attestation into it.

Example:

```bash
sbomit generate attestation.json --catalog-file existing.spdx.json --output merged.spdx.json
```

`--catalog-file` cannot be used with `--catalog`; use one catalog source per run.

## Library

Other tools can import the resolver instead of running the CLI:

```bash
go get github.com/sbomit/sbomit/pkg/resolve
```

```go
bundle, _ := os.ReadFile("attestation.json")
result, err := resolve.Resolve(bundle, resolve.Options{})
```

The result has two lists: `Packages`, each with the files it owns, and `Files`, the paths no package claimed. From a pip build (paths shortened):

```go
resolve.Result{
  Packages: []resolve.Package{{
    Name: "attrs", Version: "26.1.0", Ecosystem: "pypi",
    PURL: "pkg:pypi/attrs@26.1.0",
    // How attrs was identified.
    Evidence: []resolve.Evidence{
        {Source: "path", PkgMgr: "pip", Location: ".../site-packages/attrs-26.1.0.dist-info/METADATA"},
        {Source: "path", PkgMgr: "pip", Location: "/tmp/pip-unpack-.../attrs-26.1.0-py3-none-any.whl", Artifact: true},
        {Source: "network", PkgMgr: "pip", Location: "https://files.pythonhosted.org/.../attrs-26.1.0-py3-none-any.whl",
            Artifact: true, Digests: []resolve.Digest{{Algorithm: "sha256", Value: "c647aa4a..."}}},
        {Source: "network", PkgMgr: "pip", Location: "https://files.pythonhosted.org/.../attrs-26.1.0-py3-none-any.whl.metadata",
            Digests: []resolve.Digest{{Algorithm: "sha256", Value: "4cd40e69..."}}},
    },
    Digests: []resolve.Digest{{Algorithm: "sha256", Value: "c647aa4a..."}},
    // What attrs owns: its path evidence, plus every other file it installed.
    Files: []resolve.File{
        {Path: ".../site-packages/attrs-26.1.0.dist-info/METADATA"}, // also path evidence
        {Path: ".../site-packages/attrs-26.1.0.dist-info/RECORD", Digests: []resolve.Digest{{Algorithm: "sha256", Value: "ece8bf03..."}}},
        {Path: ".../site-packages/attrs/__init__.py", Digests: []resolve.Digest{{Algorithm: "sha256", Value: "47168064..."}}},
        {Path: ".../site-packages/attrs/converters.py", Digests: []resolve.Digest{{Algorithm: "sha256", Value: "f244258e..."}}},
        {Path: "/tmp/pip-unpack-.../attrs-26.1.0-py3-none-any.whl"}, // also path evidence
        // ...
    },
  }},
  // Paths no package claimed: the project's own files, system libraries, and so on.
  Files: []resolve.File{
    {Path: "in_toto/models/metadata.py", Digests: []resolve.Digest{{Algorithm: "sha256", Value: "dfac528d..."}}},
    {Path: "/lib/x86_64-linux-gnu/liblzma.so.5", Digests: []resolve.Digest{{Algorithm: "sha256", Value: "696e868d..."}}},
    // ...
  },
}
```

- `Package.Evidence` is every attested path (`Source: "path"`) and network-trace request (`Source: "network"`) the package was found from, with the package manager (`pip`, `conda`, `npm`, `pnpm`, `yarn`, `go`, `cargo`, `maven`, `gradle`, or empty if unknown). `Artifact` marks the file the registry publishes, as opposed to metadata or a file inside the package.
- `Package.Digests` is the artifact's sha256, set only for pypi, cargo and conda, whose registries publish that value. Other ecosystems' hashes are in their `Package.Evidence`.
- `Package.Evidence` and `Package.Files` answer different questions. `Evidence` is how the package was identified: the few patterns that let you identify a unique package. `Package.Files` is everything it owns, usually far more.
- `Files` are the attested paths no package claimed.

This data allows you to apply your own rules for how you handle each ecosystem and/or package manager.

### Library and CLI

The library reports everything in the attestation and makes no choice about what goes in the SBOM. The `sbomit` CLI reads the result with its own processing rules, set per ecosystem and package manager (`internal/generator/rules.go`, not part of the library):

- Default: install paths are the source of packages, and network requests are additional provenance. A package seen only in the network trace is not listed, since package managers download more than they install.
- npm: its `node_modules/<name>/` paths carry no version, so the network requests are the source.

By default the SBOM lists packages and only the files no package owns.
`--include-owned-files` also lists each package's files.

## Development

Common development commands are available through `make`:

```bash
make test
make build
make fmt
```

### Attestation Extractors

Modular extractors for different attestation types:
- `MaterialExtractor` - Build Input materials
- `CommandRunExtractor` - Opened files from processes
- `ProductExtractor` - Built artifacts

Implement `Extractor` interface to add new types.

### Resolvers

Ecosystem-specific package resolvers that extract packages from file paths:
- `PythonResolver` - Resolves pip from `site-packages/`, `dist-packages/`, and conda from `conda-meta/` and the package cache
- `GoResolver` - Resolves from module cache paths under `pkg/mod/`
- `RustResolver` - Resolves from Cargo registry paths
- `JavaScriptResolver` - Resolves pnpm paths under `node_modules/.pnpm/` and yarn's `.yarn/cache/`
- `JavaResolver` - Resolves from Maven repositories and the Gradle cache

Each resolver implements `Resolver` and optionally `OwnershipFilterer` to claim its own package files.

### Processing Pipeline

```
Attestation → Extract Files → Filter Cache Files → 
Run Resolvers → Filter Package Files → Generate SBOM
```

## Testing

```bash
make test
make generate-sample
``` 
   
## License  
   
Sbomit is licensed under [Apache 2.0](LICENSE.md).
   
## Contributing  
   
Contributions are welcome.
   
## Contact  
   
For any inquiries or issues, please open an issue on the [Sbomit GitHub repository](https://github.com/sbomit/sbomit/issues).
