package attestation

import "testing"

// Paths without a digest are kept: identity comes from the path.
func TestCommandRunExtractorKeepsPathsWithoutDigests(t *testing.T) {
	e := NewCommandRunExtractor()

	files := e.Extract(map[string]interface{}{
		"processes": []interface{}{
			map[string]interface{}{
				"openedfiles": map[string]interface{}{
					"/app/node_modules/.pnpm/semver@7.8.5/node_modules/semver/index.js": map[string]interface{}{
						"sha256": "abc123",
					},
					"/app/node_modules/.pnpm/semver@7.8.5/node_modules/semver": map[string]interface{}{},
					"/app/node_modules/.pnpm":                                  nil,
				},
			},
		},
	})

	if len(files) != 3 {
		t.Fatalf("expected all three paths, got %d: %v", len(files), paths(files))
	}

	byPath := make(map[string]FileInfo, len(files))
	for _, f := range files {
		byPath[f.Path] = f
	}

	withDigest := byPath["/app/node_modules/.pnpm/semver@7.8.5/node_modules/semver/index.js"]
	if want := []Digest{{"sha256", "abc123"}}; !equalDigests(withDigest.Digests, want) {
		t.Fatalf("expected the digest to be carried through, got %v", withDigest.Digests)
	}

	// A path with no digest must still arrive, with no digests rather than a
	// fabricated one.
	bare := byPath["/app/node_modules/.pnpm"]
	if len(bare.Digests) != 0 {
		t.Fatalf("expected no digests for a bare path, got %v", bare.Digests)
	}
}

func TestCommandRunExtractorDeduplicatesAcrossProcesses(t *testing.T) {
	e := NewCommandRunExtractor()

	files := e.Extract(map[string]interface{}{
		"processes": []interface{}{
			map[string]interface{}{
				"openedfiles": map[string]interface{}{
					"/usr/lib/libc.so.6": map[string]interface{}{"sha256": "aaa"},
				},
			},
			map[string]interface{}{
				"openedfiles": map[string]interface{}{
					"/usr/lib/libc.so.6": map[string]interface{}{"sha256": "aaa"},
					"/etc/ld.so.cache":   map[string]interface{}{},
				},
			},
		},
	})

	if len(files) != 2 {
		t.Fatalf("expected two distinct paths, got %d: %v", len(files), paths(files))
	}
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// The empty-content digest is dropped; the path is kept.
func TestCommandRunExtractorDropsEmptyContentDigestButKeepsPath(t *testing.T) {
	files := NewCommandRunExtractor().Extract(map[string]interface{}{
		"processes": []interface{}{
			map[string]interface{}{
				"openedfiles": map[string]interface{}{
					"/cargo/registry/cache/idx/clap_complete-4.5.55.crate": map[string]interface{}{"sha256": emptySHA256},
				},
			},
		},
	})

	if len(files) != 1 {
		t.Fatalf("the path must be kept, got %v", paths(files))
	}
	if len(files[0].Digests) != 0 {
		t.Fatalf("the empty-content digest must be dropped, got %v", files[0].Digests)
	}
}

// pip records its staged wheel empty while writing it; the process that reads
// it next records the real digest. The first record must not win.
func TestCommandRunExtractorPrefersARealDigestRecordedByALaterProcess(t *testing.T) {
	const wheel = "/tmp/pip-unpack-x/attrs-26.1.0-py3-none-any.whl"

	files := NewCommandRunExtractor().Extract(map[string]interface{}{
		"processes": []interface{}{
			map[string]interface{}{"openedfiles": map[string]interface{}{wheel: map[string]interface{}{"sha256": emptySHA256}}},
			map[string]interface{}{"openedfiles": map[string]interface{}{wheel: map[string]interface{}{}}},
			map[string]interface{}{"openedfiles": map[string]interface{}{wheel: map[string]interface{}{"sha256": "real"}}},
		},
	})

	if want := []Digest{{"sha256", "real"}}; len(files) != 1 || !equalDigests(files[0].Digests, want) {
		t.Fatalf("expected the later real digest, got %+v", files)
	}
}

// A file that changed between two processes opening it has two real digests.
// Neither is known to be the final content, so both are kept.
func TestCommandRunExtractorKeepsBothDigestsOfAFileThatChanged(t *testing.T) {
	const p = "/app/build/out.txt"

	files := NewCommandRunExtractor().Extract(map[string]interface{}{
		"processes": []interface{}{
			map[string]interface{}{"openedfiles": map[string]interface{}{p: map[string]interface{}{"sha256": "bbb"}}},
			map[string]interface{}{"openedfiles": map[string]interface{}{p: map[string]interface{}{"sha256": "aaa"}}},
		},
	})

	if want := []Digest{{"sha256", "aaa"}, {"sha256", "bbb"}}; len(files) != 1 || !equalDigests(files[0].Digests, want) {
		t.Fatalf("expected both digests, sorted, got %+v", files)
	}
}

// witness records a product as {"mime_type": ..., "digest": {...}}. Reading
// the entry itself as the digest map stored the MIME type as a hash.
func TestProductExtractorReadsTheDigestNotTheMimeType(t *testing.T) {
	files := NewProductExtractor().Extract(map[string]interface{}{
		"dist/app": map[string]interface{}{
			"mime_type": "application/octet-stream",
			"digest":    map[string]interface{}{"sha256": "d81c"},
		},
		"dist/empty": map[string]interface{}{
			"mime_type": "inode/x-empty",
			"digest":    map[string]interface{}{"sha256": emptySHA256},
		},
	})

	byPath := map[string]FileInfo{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	if want := []Digest{{"sha256", "d81c"}}; !equalDigests(byPath["dist/app"].Digests, want) {
		t.Fatalf("expected the product digest, got %v", byPath["dist/app"].Digests)
	}
	if f, ok := byPath["dist/empty"]; !ok || len(f.Digests) != 0 {
		t.Fatalf("an empty product must be kept without a digest, got %+v (present %v)", f, ok)
	}
}

// A source file is both a material and opened by the build; one entry results,
// carrying the digests of both records.
func TestExtractAllMergesAPathAcrossAttestations(t *testing.T) {
	files := NewExtractorChain().ExtractAll([]TypedAttestation{
		{Type: "material", Data: map[string]interface{}{"go.mod": map[string]interface{}{"sha256": "before"}}},
		{Type: "command-run", Data: map[string]interface{}{
			"processes": []interface{}{
				map[string]interface{}{"openedfiles": map[string]interface{}{"go.mod": map[string]interface{}{"sha256": "before"}}},
			},
		}},
		{Type: "product", Data: map[string]interface{}{
			"go.mod": map[string]interface{}{"digest": map[string]interface{}{"sha256": "after"}},
		}},
	}, nil)

	if want := []Digest{{"sha256", "after"}, {"sha256", "before"}}; len(files) != 1 || !equalDigests(files[0].Digests, want) {
		t.Fatalf("expected one merged entry, got %+v", files)
	}
}

func TestIsEmptyContentDigest(t *testing.T) {
	for _, v := range []string{
		emptySHA256,
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"gitoid:blob:sha1:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
	} {
		if !IsEmptyContentDigest(v) {
			t.Errorf("%s should be recognized as the empty-content digest", v)
		}
	}
	if IsEmptyContentDigest("23a1e53f0f5d86382dafe1cf314783b2044280f406e7e1506368220ad11b1338") {
		t.Error("a real digest was treated as empty")
	}
}

func equalDigests(got, want []Digest) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func paths(files []FileInfo) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}
