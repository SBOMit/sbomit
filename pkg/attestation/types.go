// Package attestation provides types and functions for parsing witness attestations
package attestation

// TypedAttestation represents a parsed attestation with its type and data
type TypedAttestation struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"`
}

// FileInfo is an attested path and every distinct digest recorded for it
// (possibly none, possibly several per algorithm).
type FileInfo struct {
	Path    string   `json:"path"`
	Digests []Digest `json:"digests,omitempty"`
}

// AttestationCollection represents a witness attestation collection
type AttestationCollection struct {
	Name         string                 `json:"name"`
	Attestations []TypedAttestation     `json:"attestations"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// WitnessEnvelope is the outer wrapper for witness attestations (DSSE format)
type WitnessEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature represents a DSSE signature
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// InTotoStatement represents an in-toto statement
type InTotoStatement struct {
	Type          string                 `json:"_type"`
	PredicateType string                 `json:"predicateType"`
	Subject       []Subject              `json:"subject"`
	Predicate     map[string]interface{} `json:"predicate"`
}

// Subject represents an in-toto subject
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// MaterialAttestation represents the material attestation data
type MaterialAttestation struct {
	Materials map[string]MaterialEntry `json:"materials"`
}

// MaterialEntry represents a single material entry with its hashes
type MaterialEntry struct {
	SHA256 string `json:"sha256,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
	GitOID string `json:"gitoid,omitempty"`
}

// CommandRunAttestation represents the command-run attestation data
type CommandRunAttestation struct {
	Cmd         string                     `json:"cmd"`
	OpenedFiles map[string]OpenedFileEntry `json:"openedfiles"`
	Env         map[string]string          `json:"env,omitempty"`
	Stdout      string                     `json:"stdout,omitempty"`
	Stderr      string                     `json:"stderr,omitempty"`
	ExitCode    int                        `json:"exitcode"`
}

// OpenedFileEntry represents a file that was opened during command execution
type OpenedFileEntry struct {
	SHA256 string `json:"sha256,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
	GitOID string `json:"gitoid,omitempty"`
}

// ProductAttestation represents the product attestation data
type ProductAttestation struct {
	Products map[string]ProductEntry `json:"products"`
}

// ProductEntry represents a single product entry
type ProductEntry struct {
	SHA256   string `json:"sha256,omitempty"`
	SHA1     string `json:"sha1,omitempty"`
	SHA512   string `json:"sha512,omitempty"`
	GitOID   string `json:"gitoid,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
}
