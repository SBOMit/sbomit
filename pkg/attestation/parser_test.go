package attestation

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// statement returns the in-toto statement JSON that witness puts in its DSSE
// payload, holding one attestation per given (type, data) pair.
func statementJSON(attestations string) string {
	return `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"demo","digest":{"sha256":"aa"}}],` +
		`"predicateType":"https://witness.dev/attestations/predicate/v0.1","predicate":{"attestations":[` +
		attestations + `]}}`
}

const materialJSON = `{"type":"https://witness.dev/attestations/material/v0.1",` +
	`"attestation":{"materials":{"/src/main.go":{"sha256":"aa"}}}}`
const commandRunJSON = `{"type":"commandrun","attestation":{"processes":[{"openedfiles":{` +
	`"/src/main.go":{"sha256":"aa"},"/src/util.go":{}}}]}}`

// --- ParseWitnessFile and ParseWitnessData: envelope dispatch and decoding ---

func TestParseWitnessFileReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "witness.json")
	if err := os.WriteFile(path, []byte(statementJSON(materialJSON)), 0o600); err != nil {
		t.Fatal(err)
	}

	atts, err := ParseWitnessFile(path, nil)
	if err != nil {
		t.Fatalf("parsing a real file: %v", err)
	}
	if len(atts) != 1 || atts[0].Type != "material" {
		t.Fatalf("expected one material attestation, got %+v", atts)
	}

	if _, err := ParseWitnessFile(filepath.Join(dir, "missing.json"), nil); err == nil ||
		!strings.Contains(err.Error(), "failed to read witness file") {
		t.Fatalf("expected a read error for a missing file, got %v", err)
	}
}

// A direct in-toto statement (no DSSE envelope) must parse the same way as
// the enveloped form witness usually writes.
func TestParseWitnessDataDirectStatement(t *testing.T) {
	atts, err := ParseWitnessData([]byte(statementJSON(materialJSON)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 1 {
		t.Fatalf("expected one attestation, got %d", len(atts))
	}
	if atts[0].Type != "material" {
		t.Fatalf("a URI type must canonicalize to the short name, got %q", atts[0].Type)
	}
}

func TestParseWitnessDataDSSE(t *testing.T) {
	body := statementJSON(materialJSON)

	tests := []struct {
		name string
		data string
	}{
		{"base64 payload", `{"payloadType":"application/vnd.in-toto+json","payload":"` +
			base64.StdEncoding.EncodeToString([]byte(body)) +
			`","signatures":[{"keyid":"","sig":"deadbeef"}]}`},
		{"embedded JSON payload", `{"payloadType":"application/vnd.in-toto+json","payload":` + body + `}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atts, err := ParseWitnessData([]byte(tt.data), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(atts) != 1 || atts[0].Type != "material" {
				t.Fatalf("expected one material attestation, got %+v", atts)
			}
		})
	}
}

func TestParseWitnessDataErrors(t *testing.T) {
	notJSON := "func main() {}"
	badBase64 := base64.StdEncoding.EncodeToString([]byte("<<not json>>"))

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{"invalid JSON", `{`, "failed to unmarshal attestation JSON"},
		{"no predicate, no payload", `{"subject":[]}`, "missing payload"},
		{"payload not a string or object", `{"payload":123}`, "unsupported payload format"},
		{"payload not valid base64", `{"payload":"!!!not base64!!!"}`, "failed to decode DSSE payload"},
		{"payload decodes to non-JSON", `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(notJSON)) + `"}`,
			"failed to unmarshal in-toto statement"},
		{"payload is valid base64 of bad JSON", `{"payload":"` + badBase64 + `"}`,
			"failed to unmarshal in-toto statement"},
		{"attestations is not an array", `{"predicate":{"attestations":"material"}}`, "attestations is not an array"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseWitnessData([]byte(tt.data), nil); err == nil ||
				!strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// A predicate without an "attestations" key, or with entries that are not
// objects, yields no attestations but is not an error: other producers'
// in-toto statements parse cleanly and contribute nothing.
func TestParseWitnessDataEmptyPredicate(t *testing.T) {
	for _, data := range []string{
		`{"predicate":{}}`,
		`{"predicate":{"attestations":[]}}`,
		`{"predicate":{"attestations":["a string",42]}}`,
	} {
		atts, err := ParseWitnessData([]byte(data), nil)
		if err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		if len(atts) != 0 {
			t.Fatalf("%s: expected no attestations, got %+v", data, atts)
		}
	}

	// An entry with a type but no "attestation" object survives, empty.
	atts, err := ParseWitnessData([]byte(`{"predicate":{"attestations":[{"type":"material"}]}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 1 || len(atts[0].Data) != 0 {
		t.Fatalf("expected one empty material attestation, got %+v", atts)
	}
}

// --- canonicalAttestationType ---

func TestCanonicalAttestationType(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"material", "material"},
		{"Material", "material"},
		{"  product ", "product"},
		{"", ""},
		{"   ", ""},

		// The short command-run type witness itself writes.
		{"commandrun", "command-run"},
		{"CommandRun", "command-run"},
		{"command-run", "command-run"},

		// Full URIs, in every casing, reduce to the type segment.
		{"https://witness.dev/attestations/material/v0.1", "material"},
		{"https://witness.dev/attestations/commandrun/v0.1", "command-run"},
		{"https://witness.dev/attestations/network-trace/v0.1", "network-trace"},
		{"HTTPS://Witness.Dev/Attestations/Product/V0.1", "product"},

		// Trailing slash and a version segment before the name are skipped.
		{"https://witness.dev/attestations/material/", "material"},
		{"https://witness.dev/attestations/v0.1/commandrun", "command-run"},

		// Anything else keeps its (lowercased) last useful segment.
		{"attestations/docker/v0.1", "docker"},
	}

	for _, tt := range tests {
		if got := canonicalAttestationType(tt.raw); got != tt.want {
			t.Errorf("canonicalAttestationType(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// --- type filter behavior ---

// Every spelling of a type must select the same attestations: the short name
// in any case, surrounding whitespace, or the full witness URI. Before the
// filter values were canonicalized, the URI form matched nothing and the
// capitalized form lost its files at extraction.
func TestTypeFilterAcceptsAllSpellings(t *testing.T) {
	data := []byte(statementJSON(materialJSON + "," + commandRunJSON))

	tests := []struct {
		name   string
		filter []string
		want   []string
	}{
		{"no filter", nil, []string{"material", "command-run"}},
		{"empty filter", []string{}, []string{"material", "command-run"}},
		{"short name", []string{"material"}, []string{"material"}},
		{"capitalized", []string{"Material"}, []string{"material"}},
		{"padded", []string{" material "}, []string{"material"}},
		{"command run spelling", []string{"command-run"}, []string{"command-run"}},
		{"uri style", []string{"https://witness.dev/attestations/material/v0.1"}, []string{"material"}},
		{"multiple", []string{"commandrun", "https://witness.dev/attestations/material/v0.1"},
			[]string{"material", "command-run"}},
		{"unknown selects nothing", []string{"docker"}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atts, err := ParseWitnessData(data, tt.filter)
			if err != nil {
				t.Fatal(err)
			}

			got := make([]string, 0, len(atts))
			for _, a := range atts {
				got = append(got, a.Type)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("filter %v: got %v, want %v", tt.filter, got, tt.want)
			}

			// Parsing and extraction must agree: whatever the filter keeps,
			// ExtractAll sees with the same filter.
			files := ExtractFilesFromAttestations(atts, tt.filter)
			if len(tt.want) == 0 {
				if len(files) != 0 {
					t.Fatalf("an unmatched filter must extract nothing, got %v", paths(files))
				}
				return
			}
			// Both attestations name /src/main.go; /src/util.go comes from
			// command-run only. Map iteration order is not stable, so
			// compare sorted path sets.
			wantPaths := []string{"/src/main.go"}
			for _, typ := range tt.want {
				if typ == "command-run" {
					wantPaths = []string{"/src/main.go", "/src/util.go"}
				}
			}
			gotPaths := paths(files)
			sort.Strings(gotPaths)
			sort.Strings(wantPaths)
			if strings.Join(gotPaths, ",") != strings.Join(wantPaths, ",") {
				t.Fatalf("expected %v, got %v", wantPaths, gotPaths)
			}
		})
	}
}

// An attestation recorded without a type is kept when unfiltered and dropped
// by any filter.
func TestTypeFilterDropsUntypedAttestations(t *testing.T) {
	data := []byte(`{"predicate":{"attestations":[{"attestation":{"/f.go":{}}}]}}`)

	atts, err := ParseWitnessData(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 1 || atts[0].Type != "" {
		t.Fatalf("an untyped attestation must survive an empty filter, got %+v", atts)
	}

	if atts, err := ParseWitnessData(data, []string{"material"}); err != nil || len(atts) != 0 {
		t.Fatalf("an untyped attestation must not pass a filter, got %+v (%v)", atts, err)
	}
}

// ExtractAll is also called with hand-built attestations; a URI type there
// must find its extractor too, not just at parse time.
func TestExtractAllCanonicalizesHandBuiltTypes(t *testing.T) {
	atts := []TypedAttestation{{
		Type: "https://witness.dev/attestations/material/v0.1",
		Data: map[string]interface{}{"/src/main.go": map[string]interface{}{"sha256": "aa"}},
	}}

	for _, filter := range [][]string{nil, {"material"},
		{"https://witness.dev/attestations/material/v0.1"}} {
		files := NewExtractorChain().ExtractAll(atts, filter)
		if len(files) != 1 || files[0].Path != "/src/main.go" {
			t.Fatalf("filter %v: expected the material file, got %v", filter, paths(files))
		}
	}
}
