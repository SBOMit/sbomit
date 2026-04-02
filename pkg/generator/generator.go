package generator

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sbomit/sbomit/pkg/attestation"
	"github.com/sbomit/sbomit/pkg/resolver"
	"github.com/sbomit/sbomit/pkg/resolver/network"
)

type Options struct {
	DocumentName     string
	DocumentVersion  string
	Authors          []string
	AttestationTypes []string
	OutputFormat     string
	OutputPath       string
	Catalog          string
	ProjectDir       string
}

// DefaultOptions returns default generator options
func DefaultOptions() *Options {
	return &Options{
		DocumentName:     "sbomit-generated-sbom",
		DocumentVersion:  "0.0.1",
		Authors:          []string{},
		AttestationTypes: []string{"material", "command-run", "product", "network-trace"},
		OutputFormat:     "spdx23",
		Catalog:          "",
		ProjectDir:       "",
	}
}

type Generator struct {
	opts          *Options
	resolverChain *resolver.ResolverChain
	networkChain  *network.Chain
}

func New(opts *Options) *Generator {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Generator{
		opts:          opts,
		resolverChain: resolver.NewResolverChain(),
		networkChain:  network.NewChain(),
	}
}

func (g *Generator) GenerateFromFile(attestationPath string) error {
	attestations, err := attestation.ParseWitnessFile(attestationPath, g.opts.AttestationTypes)
	if err != nil {
		return fmt.Errorf("failed to parse attestation file: %w", err)
	}
	g.printParsedAttestationSummary(attestations)
	return g.GenerateFromAttestations(attestations)
}

func (g *Generator) printParsedAttestationSummary(attestations []attestation.TypedAttestation) {
	counts := make(map[string]int)
	for _, att := range attestations {
		counts[att.Type]++
	}

	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)

	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s=%d", t, counts[t]))
	}
	if len(parts) == 0 {
		parts = append(parts, "none")
	}

	fmt.Fprintf(os.Stderr, "Parsed attestations (%d total): %s\n", len(attestations), strings.Join(parts, ", "))
}

func (g *Generator) GenerateFromAttestations(attestations []attestation.TypedAttestation) error {
	var baseDoc *sbom.Document
	var err error

	projectDir := strings.TrimSpace(g.opts.ProjectDir)
	if projectDir == "" {
		projectDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to determine project directory: %w", err)
		}
	}

	switch g.opts.Catalog {
	case "syft":
		baseDoc, err = g.runSyft(projectDir)
		if err != nil {
			return fmt.Errorf("failed to run syft: %w", err)
		}
	case "trivy":
		baseDoc, err = g.runTrivy(projectDir)
		if err != nil {
			return fmt.Errorf("failed to run trivy: %w", err)
		}
	default:
	}

	attFiles := attestation.ExtractFilesFromAttestations(attestations, g.opts.AttestationTypes)

	// Convert to resolver.FileInfo format
	var files []resolver.FileInfo
	for _, f := range attFiles {
		files = append(files, resolver.FileInfo{
			Path:   f.Path,
			Hashes: f.Hashes,
		})
	}

	// Run through resolver chain (filtering + resolution)
	result := g.resolverChain.ResolveAll(files)

	// Resolve packages from network connections
	networkConns := network.ExtractConnections(attestations)
	networkPkgs := g.networkChain.ResolveAll(networkConns)
	result = mergeNetworkPackages(result, networkPkgs)

	attDoc := g.createDocument(result)

	if baseDoc != nil {
		g.applyMetadata(baseDoc)
		g.mergePreferAttestation(baseDoc, attDoc)
		return g.writeOutput(baseDoc)
	}

	return g.writeOutput(attDoc)
}

// mergeNetworkPackages merges network-resolved packages into the file-resolved result.
//
// If a package is already present (matched by PURL), the download URL and IP from the
// network connection are appended as PURL qualifiers:
//
//	pkg:pypi/certifi@2025.11.12?url=https://files.pythonhosted.org/...&ip=151.101.128.223
//
// If the package is not yet in the SBOM it is appended as a new entry.
func mergeNetworkPackages(result resolver.ResolverResult, networkPkgs []resolver.PackageInfo) resolver.ResolverResult {
	if len(networkPkgs) == 0 {
		return result
	}

	existingByPURL := make(map[string]int, len(result.Packages))
	for i, pkg := range result.Packages {
		existingByPURL[pkg.PURL] = i
	}

	for _, npkg := range networkPkgs {
		if idx, found := existingByPURL[npkg.PURL]; found {
			result.Packages[idx].PURL = withNetworkQualifiers(result.Packages[idx].PURL, npkg.DownloadURL, npkg.DownloadIP)
		} else {
			result.Packages = append(result.Packages, npkg)
			existingByPURL[npkg.PURL] = len(result.Packages) - 1
		}
	}

	return result
}

// withNetworkQualifiers appends ?url=...&ip=... qualifiers to a PURL.
// Values are percent-encoded per RFC 3986 as required by the PURL spec.
func withNetworkQualifiers(purl, downloadURL, downloadIP string) string {
	if downloadURL == "" && downloadIP == "" {
		return purl
	}

	sep := "?"
	if strings.Contains(purl, "?") {
		sep = "&"
	}

	var parts []string
	if downloadURL != "" {
		parts = append(parts, "url="+purlEncodeValue(downloadURL))
	}
	if downloadIP != "" {
		parts = append(parts, "ip="+purlEncodeValue(downloadIP))
	}

	return purl + sep + strings.Join(parts, "&")
}

// purlEncodeValue percent-encodes a PURL qualifier value (RFC 3986 §2.1).
// We encode the characters that would otherwise break PURL parsing: & = ? #
func purlEncodeValue(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '&', '=', '?', '#', '%':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (g *Generator) createDocument(result resolver.ResolverResult) *sbom.Document {
	doc := sbom.NewDocument()

	doc.Metadata.Id = fmt.Sprintf("urn:uuid:%s", generateUUID())
	doc.Metadata.Name = g.opts.DocumentName
	doc.Metadata.Version = g.opts.DocumentVersion
	doc.Metadata.Date = timestamppb.New(time.Now())

	for _, author := range g.opts.Authors {
		doc.Metadata.Authors = append(doc.Metadata.Authors, &sbom.Person{Name: author})
	}

	doc.Metadata.Tools = append(doc.Metadata.Tools, &sbom.Tool{
		Name:    "sbomit",
		Version: "0.0.1",
		Vendor:  "SBOMit",
	})

	appNode := &sbom.Node{
		Id:             fmt.Sprintf("pkg:generic/%s@%s", sanitizeID(g.opts.DocumentName), g.opts.DocumentVersion),
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
		Name:           g.opts.DocumentName,
		Version:        g.opts.DocumentVersion,
	}

	doc.NodeList.AddRootNode(appNode)

	// Add resolved packages
	for _, pkg := range result.Packages {
		node := g.createPackageNode(pkg)
		doc.NodeList.AddNode(node)
		doc.NodeList.RelateNodeAtID(node, appNode.Id, sbom.Edge_contains)
	}

	// Add unresolved files
	for _, file := range result.Files {
		node := g.createFileNode(file)
		doc.NodeList.AddNode(node)
		doc.NodeList.RelateNodeAtID(node, appNode.Id, sbom.Edge_contains)
	}

	return doc
}

func (g *Generator) applyMetadata(doc *sbom.Document) {
	if doc.Metadata == nil {
		doc.Metadata = &sbom.Metadata{}
	}

	if doc.Metadata.Name == "" {
		doc.Metadata.Name = g.opts.DocumentName
	}
	if doc.Metadata.Version == "" {
		doc.Metadata.Version = g.opts.DocumentVersion
	}
	if doc.Metadata.Date == nil {
		doc.Metadata.Date = timestamppb.New(time.Now())
	}

	for _, author := range g.opts.Authors {
		doc.Metadata.Authors = append(doc.Metadata.Authors, &sbom.Person{Name: author})
	}

	doc.Metadata.Tools = append(doc.Metadata.Tools, &sbom.Tool{
		Name:    "sbomit",
		Version: "0.0.1",
		Vendor:  "SBOMit",
	})
}

func (g *Generator) mergePreferAttestation(baseDoc *sbom.Document, attDoc *sbom.Document) {
	if baseDoc == nil || baseDoc.NodeList == nil || attDoc == nil || attDoc.NodeList == nil {
		return
	}

	// Index syft nodes by both ID and PURL for deduplication
	baseIndexByID := map[string]*sbom.Node{}
	baseIndexByPURL := map[string]*sbom.Node{}

	for _, node := range baseDoc.NodeList.Nodes {
		if node == nil || node.Id == "" {
			continue
		}
		baseIndexByID[node.Id] = node

		purl := string(node.Purl())
		if purl != "" {
			baseIndexByPURL[strings.ToLower(purl)] = node
		}
	}

	// Merge attestation nodes, preferring attestation values on conflict
	for _, attNode := range attDoc.NodeList.Nodes {
		if attNode == nil || attNode.Id == "" {
			continue
		}

		var targetNode *sbom.Node

		// First try to match by PURL (this handles different ID schemes)
		attPurl := string(attNode.Purl())
		if attPurl != "" {
			if baseNode, ok := baseIndexByPURL[strings.ToLower(attPurl)]; ok {
				targetNode = baseNode
			}
		}

		// Fallback to ID match if no PURL match
		if targetNode == nil {
			if baseNode, ok := baseIndexByID[attNode.Id]; ok {
				targetNode = baseNode
			}
		}

		if targetNode != nil {
			// Merge: prefer attestation values over syft
			targetNode.Update(attNode)
		} else {
			// New node from attestation
			baseDoc.NodeList.AddNode(attNode)
			baseIndexByID[attNode.Id] = attNode
			if attPurl != "" {
				baseIndexByPURL[strings.ToLower(attPurl)] = attNode
			}
		}
	}

	// Merge edges and root elements from attestation doc
	mergeList := sbom.NewNodeList()
	mergeList.Edges = attDoc.NodeList.Edges
	mergeList.RootElements = attDoc.NodeList.RootElements
	baseDoc.NodeList.Add(mergeList)
}

func (g *Generator) runSyft(projectDir string) (*sbom.Document, error) {
	if _, err := exec.LookPath("syft"); err != nil {
		return nil, fmt.Errorf("syft not found in PATH. Install options:\n  - macOS (brew): brew install syft\n  - go install: go install github.com/anchore/syft/cmd/syft@latest\n  - other platforms: https://github.com/anchore/syft#installation")
	}

	tmpFile, err := os.CreateTemp("", "sbomit-syft-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	var stderr bytes.Buffer
	cmd := exec.Command("syft", projectDir, "-o", "spdx-json")
	cmd.Stdout = tmpFile
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	if err := tmpFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync syft output: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close syft output: %w", err)
	}

	r := reader.New()
	return r.ParseFile(tmpFile.Name())
}

func (g *Generator) runTrivy(projectDir string) (*sbom.Document, error) {
	if _, err := exec.LookPath("trivy"); err != nil {
		return nil, fmt.Errorf("trivy not found in PATH. Install options:\n  - macOS (brew): brew install aquasecurity/trivy/trivy\n  - other platforms: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
	}

	tmpFile, err := os.CreateTemp("", "sbomit-trivy-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	var stderr bytes.Buffer
	// Tell Trivy to scan the directory and output an SPDX JSON file
	cmd := exec.Command("trivy", "fs", "--format", "spdx-json", "--output", tmpFile.Name(), projectDir)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	// Parse the SBOM using protobom (the same way we do with Syft)
	r := reader.New()
	return r.ParseFile(tmpFile.Name())
}

func (g *Generator) createPackageNode(pkg resolver.PackageInfo) *sbom.Node {
	node := &sbom.Node{
		Id:             pkg.PURL,
		Type:           sbom.Node_PACKAGE,
		Name:           pkg.Name,
		Version:        pkg.Version,
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		Licenses:       pkg.Licenses,
		Identifiers:    make(map[int32]string),
		Hashes:         make(map[int32]string),
	}

	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = pkg.PURL

	for algo, hash := range pkg.Hashes {
		hashAlgo := mapHashAlgorithm(algo)
		if hashAlgo != sbom.HashAlgorithm_UNKNOWN {
			node.Hashes[int32(hashAlgo)] = hash
		}
	}

	return node
}

func (g *Generator) createFileNode(file resolver.FileInfo) *sbom.Node {
	node := &sbom.Node{
		Id:     fmt.Sprintf("File-%s", sanitizeID(file.Path)),
		Type:   sbom.Node_FILE,
		Name:   file.Path,
		Hashes: make(map[int32]string),
	}

	for algo, hash := range file.Hashes {
		hashAlgo := mapHashAlgorithm(algo)
		if hashAlgo != sbom.HashAlgorithm_UNKNOWN {
			node.Hashes[int32(hashAlgo)] = hash
		}
	}

	return node
}

// nopWriteCloser wraps os.File to implement io.WriteCloser
type nopWriteCloser struct {
	w *os.File
}

func (n *nopWriteCloser) Write(p []byte) (int, error) {
	return n.w.Write(p)
}

func (n *nopWriteCloser) Close() error {
	if n.w == os.Stdout {
		return nil
	}
	return n.w.Close()
}

func (g *Generator) writeOutput(doc *sbom.Document) error {
	w := writer.New()
	format := g.getOutputFormat()

	if g.opts.OutputPath == "" || g.opts.OutputPath == "-" {
		return w.WriteStreamWithOptions(doc, &nopWriteCloser{w: os.Stdout}, &writer.Options{Format: format})
	}

	return w.WriteFileWithOptions(doc, g.opts.OutputPath, &writer.Options{Format: format})
}

func (g *Generator) getOutputFormat() formats.Format {
	switch strings.ToLower(g.opts.OutputFormat) {
	case "spdx23", "spdx-2.3", "spdx23json":
		return formats.SPDX23JSON
	case "spdx22", "spdx-2.2", "spdx22json":
		return formats.SPDX22JSON
	case "cdx14", "cdx-1.4", "cdx14json", "cyclonedx14":
		return formats.CDX14JSON
	case "cdx15", "cdx-1.5", "cdx15json", "cyclonedx15":
		return formats.CDX15JSON
	default:
		return formats.SPDX23JSON
	}
}

func mapHashAlgorithm(algo string) sbom.HashAlgorithm {
	switch strings.ToLower(algo) {
	case "sha256", "sha-256":
		return sbom.HashAlgorithm_SHA256
	case "sha1", "sha-1":
		return sbom.HashAlgorithm_SHA1
	case "sha512", "sha-512":
		return sbom.HashAlgorithm_SHA512
	case "md5":
		return sbom.HashAlgorithm_MD5
	case "sha384", "sha-384":
		return sbom.HashAlgorithm_SHA384
	default:
		return sbom.HashAlgorithm_UNKNOWN
	}
}

func sanitizeID(s string) string {
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		" ", "-",
		":", "-",
		"@", "-at-",
	)
	result := replacer.Replace(s)
	result = strings.Trim(result, "-")
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	return result
}

func generateUUID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		now&0xFFFFFFFF,
		(now>>32)&0xFFFF,
		(now>>48)&0xFFFF,
		(now>>16)&0xFFFF,
		now&0xFFFFFFFFFFFF,
	)
}
