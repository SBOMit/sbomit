package hashlookup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const libcHash = "2fd7c8f96a208532befb77cec1cfee8a08217a97b77d8eed382537fa6cc6e72c"

func TestClientAttribute(t *testing.T) {
	var got attributeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/attribute" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{
		  "hint": {"distro": "ubuntu", "suite": "noble", "arch": "arm64"},
		  "packages": [
		    {"name": "libc6", "arch": "arm64", "exact": true, "versions": ["2.39-0ubuntu8.6"],
		     "purl": "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.6?arch=arm64&upstream=glibc&distro=ubuntu-24.04",
		     "files_matched": [{"path": "/lib/aarch64-linux-gnu/libc.so.6", "sha256": "x", "evidence": "hash"}],
		     "anchors": 8},
		    {"name": "python3-pip", "arch": "all", "exact": false, "versions": ["24.0+dfsg-1ubuntu1", "24.0+dfsg-1ubuntu1.3"],
		     "purl": "pkg:deb/ubuntu/python3-pip?arch=all&distro=ubuntu-24.04", "files_matched": []}
		  ],
		  "misses": []
		}`))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL + "/"}
	res, err := c.Attribute(context.Background(), []File{{Path: "/lib/aarch64-linux-gnu/libc.so.6", SHA256: libcHash}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || got.Files[0].SHA256 != libcHash {
		t.Fatalf("request = %+v", got)
	}
	if res.Distro != "ubuntu" || res.Suite != "noble" || res.Arch != "arm64" || len(res.Packages) != 2 {
		t.Fatalf("result = %+v", res)
	}
	libc, pip := res.Packages[0], res.Packages[1]
	if libc.Version() != "2.39-0ubuntu8.6" || libc.Files[0].Evidence != EvidenceHash {
		t.Fatalf("libc6 = %+v", libc)
	}
	if pip.Version() != "" || pip.Exact {
		t.Fatalf("ambiguous package must have no version: %+v", pip)
	}
}

func TestClientErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "index unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL}
	_, err := c.Attribute(context.Background(), []File{{Path: "/usr/bin/ls", SHA256: libcHash}})
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "index unavailable") {
		t.Fatalf("want 503 error with body, got %v", err)
	}

	// No files: no request at all.
	none := &Client{URL: "http://127.0.0.1:1"}
	if res, err := none.Attribute(context.Background(), nil); err != nil || len(res.Packages) != 0 {
		t.Fatalf("empty input = %+v %v", res, err)
	}
	if _, err := none.Attribute(context.Background(), make([]File, MaxFiles+1)); err == nil {
		t.Fatal("expected limit error")
	}
}

func TestCandidate(t *testing.T) {
	for _, tc := range []struct {
		path string
		shas []string
		ok   bool
	}{
		{"/lib/aarch64-linux-gnu/libc.so.6", []string{libcHash}, true},
		{"/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/libc.so", []string{libcHash}, true},
		{"/etc/os-release", []string{strings.ToUpper(libcHash)}, true},
		{"/usr/local/lib/python3.12/site-packages/x.py", []string{libcHash}, false}, // not dpkg
		{"/home/runner/work/app/main.go", []string{libcHash}, false},                // workspace: never sent
		{"/tmp/build/x.o", []string{libcHash}, false},
		{"relative/path", []string{libcHash}, false},
		{"/usr/bin/ls", nil, false},                          // no digest
		{"/usr/bin/ls", []string{libcHash, libcHash}, false}, // changed during the build
		{"/usr/bin/ls", []string{"short"}, false},
	} {
		f, ok := Candidate(tc.path, tc.shas)
		if ok != tc.ok {
			t.Errorf("Candidate(%s) ok=%v, want %v", tc.path, ok, tc.ok)
		}
		if ok && (f.SHA256 != libcHash || strings.Contains(f.Path, "..")) {
			t.Errorf("Candidate(%s) = %+v", tc.path, f)
		}
	}
}
