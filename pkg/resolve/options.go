package resolve

import (
	"time"

	"github.com/sbomit/sbomit/pkg/hashlookup"
)

// Options controls resolution. The zero value is valid.
type Options struct {
	// AttestationTypes is the list of attestation types to parse.
	// If empty, defaults to: material, command-run, product, network-trace.
	AttestationTypes []string

	// ExcludePaths are filepath.Match globs applied on top of the built-in
	// filter that already removes caches, build scratch and other noise.
	ExcludePaths []string

	// HashLookup, when set, attributes the files no path resolver claimed to
	// OS packages (deb) by their sha256, after the resolver chain runs. Only
	// system paths (/usr, /lib, /bin, /etc, ...) are sent to it. Nil (the
	// default) disables it: no network calls are made.
	HashLookup hashlookup.Attributor

	// HashLookupTimeout bounds the HashLookup call (default 60s).
	HashLookupTimeout time.Duration
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
