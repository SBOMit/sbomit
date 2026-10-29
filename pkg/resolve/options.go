package resolve

// Options controls resolution. The zero value is valid.
type Options struct {
	// AttestationTypes is the list of attestation types to parse.
	// If empty, defaults to: material, command-run, product, network-trace.
	AttestationTypes []string

	// ExcludePaths are filepath.Match globs applied on top of the built-in
	// filter that already removes caches, build scratch and other noise.
	ExcludePaths []string

	// OmitOwnedFiles leaves only unclaimed paths in Result.Files. Ownership is
	// in Result.Relationships either way.
	OmitOwnedFiles bool
}

// defaultAttestationTypes are the attestation types parsed when
// Options.AttestationTypes is nil or empty.
var defaultAttestationTypes = []string{
	"material",
	"command-run",
	"product",
	"network-trace",
}

// attestationTypes returns the configured types, or the defaults.
func (o *Options) attestationTypes() []string {
	if len(o.AttestationTypes) > 0 {
		return o.AttestationTypes
	}
	return defaultAttestationTypes
}
