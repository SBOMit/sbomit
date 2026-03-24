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
  -c, --catalog string       Cataloger to run before processing attestations (supported: syft)
  -f, --format string        SBOM output format (supported: spdx23, spdx22, cdx14, cdx15) (default "spdx23")
  -h, --help                 help for generate
  -n, --name string          Name for the SBOM document (default "sbomit-sbom")
  -o, --output string        Output file path (default: stdout)
      --project-dir string   Project directory to scan with the cataloger (default: current directory)
      --types strings        Attestation types to parse (comma-separated). (default [material,command-run,product,network-trace])
  -v, --version string       Version for the SBOM document (default "0.0.1")
```

By default, `sbomit` parses `material`, `command-run`, and `product` attestations. To restrict parsing on demand:

```bash
sbomit generate attestation.json --types command-run
```

## Syft Catalog Option

Sbomit outputs a flat list of dependencies. If the SBOM metadata syft derives includes dependency structure, using syft first can help preserve more relationship context.

Example:

```bash
sbomit generate attestation.json --catalog syft --project-dir /path/to/project
```

## Development

### Attestation Extractors

Modular extractors for different attestation types:
- `MaterialExtractor` - Build Input materials
- `CommandRunExtractor` - Opened files from processes
- `ProductExtractor` - Built artifacts

Implement `Extractor` interface to add new types.

### Resolvers

Ecosystem-specific package resolvers that extract packages from file paths:
- `PythonResolver` - Resolves from `site-packages/`, `dist-packages/`, `.dist-info`
- `GoResolver` - Resolves from module cache paths under `pkg/mod/`
- `RustResolver` - Resolves from Cargo registry paths
- `JavaScriptResolver` - Resolves pnpm-style paths under `node_modules/.pnpm/`

Each resolver implements `Resolver` and optionally `PackageFileFilterer` to filter its own package files.

### Processing Pipeline

```
Attestation → Extract Files → Filter Cache Files → 
Run Resolvers → Filter Package Files → Generate SBOM
```

## Testing

```bash
go run . generate test/sample-attestation.json
``` 
   
## License  
   
Sbomit is licensed under [Apache 2.0](LICENSE).
   
## Contributing  
   
Contributions are welcome.
   
## Contact  
   
For any inquiries or issues, please open an issue on the [Sbomit GitHub repository](https://github.com/sbomit/sbomit/issues).
