package resolve

// Options controls resolution. The zero value is valid.
type Options struct {
	// AttestationTypes is the list of attestation types to parse.
	// If empty, defaults to: material, command-run, product.
	AttestationTypes []string

	// ExcludePaths are filepath.Match globs applied on top of the built-in
	// filter that already removes caches, build scratch and other noise.
	ExcludePaths []string

	// OmitOwnedFiles drops package-owned files from Result.Files, leaving only
	// the paths no package claimed. Ownership is in Result.Relationships
	// either way, so this trades completeness for a leaner file list.
	//
	// Off by default: owned files are included, which is what an SBOM consumer
	// wants. Callers who want only the leftovers can use [Result.UnownedFiles] instead.
	OmitOwnedFiles bool
}

// defaultAttestationTypes are the attestation types parsed when
// Options.AttestationTypes is nil or empty.
var defaultAttestationTypes = []string{
	"material",
	"command-run",
	"product",
}

// attestationTypes returns the configured types, or the defaults.
func (o *Options) attestationTypes() []string {
	if len(o.AttestationTypes) > 0 {
		return o.AttestationTypes
	}
	return defaultAttestationTypes
}
