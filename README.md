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

The result has three lists: `Packages`, `Files` and `Relationships`. For one package from a pip build (paths shortened):

```go
resolve.Package{
    ID: "0171d0cf40b8148f", Name: "attrs", Version: "26.1.0", Ecosystem: "pypi",
    PURL: "pkg:pypi/attrs@26.1.0",
    Evidence: []resolve.Evidence{
        {Source: "path", PkgMgr: "pip", Location: ".../site-packages/attrs-26.1.0.dist-info/METADATA"},
        {Source: "path", PkgMgr: "pip", Location: "/tmp/pip-unpack-.../attrs-26.1.0-py3-none-any.whl", Artifact: true},
        {Source: "network", PkgMgr: "pip", Location: "https://files.pythonhosted.org/.../attrs-26.1.0-py3-none-any.whl",
            Artifact: true, Digests: []resolve.Digest{{Algorithm: "sha256", Value: "c647aa4a..."}}},
        {Source: "network", PkgMgr: "pip", Location: "https://files.pythonhosted.org/.../attrs-26.1.0-py3-none-any.whl.metadata",
            Digests: []resolve.Digest{{Algorithm: "sha256", Value: "4cd40e69..."}}},
    },
    Digests: []resolve.Digest{{Algorithm: "sha256", Value: "c647aa4a..."}},
}

resolve.File{Path: ".../attrs-26.1.0.dist-info/RECORD", Digests: []resolve.Digest{{Algorithm: "sha256", Value: "ece8bf03..."}}}

resolve.Relationship{Type: "evident-by", FromPackageID: "0171d0cf40b8148f", ToPath: ".../attrs-26.1.0.dist-info/METADATA"}
resolve.Relationship{Type: "contains", FromPackageID: "0171d0cf40b8148f", ToPath: ".../site-packages/attrs/__init__.py"}
```

- `Evidence` is every attested path (`Source: "path"`) and network-trace request (`Source: "network"`) the package was found from, with the package manager (`pip`, `conda`, `npm`, `pnpm`, `yarn`, `go`, `cargo`, `maven`, `gradle`, or empty if unknown). `Artifact` marks the file the registry publishes, as opposed to metadata or a file inside the package.
- `Package.Digests` is the artifact's sha256, set only for pypi, cargo and conda, whose registries publish that value. Other ecosystems' hashes stay on their `Evidence`.
- `Files` is every attested path with its recorded digests. `Relationships` say which package owns (`contains`) or was identified by (`evident-by`) each path.

This data allows you to apply your own policy to reason about how you handle each ecosystem and/or package manager.

### Library and CLI

The library reports everything in the attestation and makes no choice about which packages to list. The `sbomit` CLI applies its own policy on top (`internal/generator/policy.go`, not part of the library):

TLDR of the current policy:
- Package names and versions come from install paths. A package with path evidence is listed, and its network requests are additional provenance.
- A package seen only in the network trace is not listed, since package managers download more than they install. The exception is npm: its `node_modules/<name>/` paths carry no version, so a `.tgz` downloaded by npm is listed.

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
