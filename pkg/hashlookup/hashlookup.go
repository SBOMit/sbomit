// Package hashlookup attributes attested OS files (shared libraries,
// binaries, headers, configs) to the distro packages that ship them, by
// content hash.
//
// Path patterns can't do this: /usr/lib/aarch64-linux-gnu/libc.so.6 carries
// no version. But witness records a sha256 for every file, and a file-hash
// index of the distro archive maps that hash to the exact package version
// (see https://github.com/jd869/debhash).
//
// Only absolute system paths are sent to the service (see Candidates), never
// workspace, home or /usr/local paths.
package hashlookup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// File is an attested file to attribute.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Evidence says how a file was tied to its package.
type Evidence string

const (
	// EvidenceHash: the file's sha256 is shipped by the package.
	EvidenceHash Evidence = "hash"
	// EvidencePycSource: a generated __pycache__/*.pyc whose .py source the
	// package ships (bytecode is never in a .deb).
	EvidencePycSource Evidence = "pyc-source"
)

// Match is one attested file assigned to a package.
type Match struct {
	Path     string   `json:"path"`
	Evidence Evidence `json:"evidence"`
}

// Package is a distro package identified from file hashes.
type Package struct {
	Name string `json:"name"`
	Arch string `json:"arch"`
	// Exact is true when the files narrow the package to one version.
	// Otherwise Version is empty, PURL has no version and Versions lists
	// the candidates (e.g. pure-Python packages whose files didn't change).
	Exact    bool     `json:"exact"`
	Versions []string `json:"versions"`
	PURL     string   `json:"purl"`
	Files    []Match  `json:"files_matched"`
}

// Version returns the exact version, or "" when it is ambiguous.
func (p Package) Version() string {
	if p.Exact && len(p.Versions) == 1 {
		return p.Versions[0]
	}
	return ""
}

// Result is the outcome of attributing a set of files.
type Result struct {
	// Distro, Suite and Arch are the system the files came from, as given
	// or as detected by the service.
	Distro, Suite, Arch string
	Packages            []Package
}

// Attributor attributes files to packages. Client implements it; tests can
// substitute a fake.
type Attributor interface {
	Attribute(ctx context.Context, files []File) (*Result, error)
}

// Client calls a debhash-compatible service's POST /v1/attribute.
type Client struct {
	// URL is the service base URL, e.g. http://127.0.0.1:8080.
	URL  string
	HTTP *http.Client
}

type attributeRequest struct {
	Files []File `json:"files"`
}

type attributeResponse struct {
	Hint struct {
		Distro string `json:"distro"`
		Suite  string `json:"suite"`
		Arch   string `json:"arch"`
	} `json:"hint"`
	Packages []Package `json:"packages"`
}

// MaxFiles is the most files sent in one request (the service's limit).
const MaxFiles = 20000

// Attribute sends files to the service. It sends nothing and returns an
// empty Result when there are no files.
func (c *Client) Attribute(ctx context.Context, files []File) (*Result, error) {
	if len(files) == 0 {
		return &Result{}, nil
	}
	if len(files) > MaxFiles {
		return nil, fmt.Errorf("hash lookup: %d files exceeds the limit of %d", len(files), MaxFiles)
	}
	body, err := json.Marshal(attributeRequest{Files: files})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+"/v1/attribute", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hash lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hash lookup: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var out attributeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("hash lookup: decode response: %w", err)
	}
	return &Result{Distro: out.Hint.Distro, Suite: out.Hint.Suite, Arch: out.Hint.Arch, Packages: out.Packages}, nil
}

// systemPrefixes are where distro packages install files.
var systemPrefixes = []string{"/usr/", "/lib/", "/lib64/", "/lib32/", "/bin/", "/sbin/", "/etc/", "/opt/"}

// IsSystemPath reports whether p is where a distro package could have put a
// file. /usr/local is excluded: dpkg never installs there.
func IsSystemPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "/usr/local/") {
		return false
	}
	for _, pre := range systemPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Candidate turns an attested path and its sha256 values into a File to
// send, or reports false: non-system paths are never sent, and a file whose
// content changed during the build (two sha256 values) is ambiguous.
func Candidate(p string, sha256s []string) (File, bool) {
	p = path.Clean(p)
	if !IsSystemPath(p) || len(sha256s) != 1 || len(sha256s[0]) != 64 {
		return File{}, false
	}
	return File{Path: p, SHA256: strings.ToLower(sha256s[0])}, true
}
