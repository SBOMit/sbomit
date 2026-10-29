package attestation

import (
	"sort"
	"strings"
)

// Digest is a hash algorithm and its hex-encoded value.
type Digest struct {
	Algorithm string
	Value     string
}

// emptyContentDigests are the digests of zero bytes, gitoid included. witness
// might record them for files it hashed while they were still being written,
// they are dropped; for genuinely empty files they identify nothing anyway.
var emptyContentDigests = map[string]struct{}{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":                                                                 {}, // sha256
	"da39a3ee5e6b4b0d3255bfef95601890afd80709":                                                                                         {}, // sha1
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e": {}, // sha512
	"d41d8cd98f00b204e9800998ecf8427e":                                                                                                 {}, // md5
	"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391":                                                                                         {}, // gitoid:blob:sha1
	"473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813":                                                                 {}, // gitoid:blob:sha256
}

func IsEmptyContentDigest(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if i := strings.LastIndex(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	_, empty := emptyContentDigests[v]
	return empty
}

// AddDigest appends a digest unless it is empty, the empty-content digest, or
// already present. Different values for one algorithm are all kept.
func AddDigest(digests []Digest, algorithm, value string) []Digest {
	if algorithm == "" || value == "" || IsEmptyContentDigest(value) {
		return digests
	}
	for _, d := range digests {
		if d.Algorithm == algorithm && d.Value == value {
			return digests
		}
	}
	return append(digests, Digest{Algorithm: algorithm, Value: value})
}

// MergeDigests adds every digest of src to dst, by the rules of AddDigest.
func MergeDigests(dst, src []Digest) []Digest {
	for _, d := range src {
		dst = AddDigest(dst, d.Algorithm, d.Value)
	}
	return dst
}

// SortDigests orders digests by algorithm, then value.
func SortDigests(digests []Digest) {
	sort.Slice(digests, func(i, j int) bool {
		if digests[i].Algorithm != digests[j].Algorithm {
			return digests[i].Algorithm < digests[j].Algorithm
		}
		return digests[i].Value < digests[j].Value
	})
}

// parseDigests reads witness's algorithm -> value map for one path.
func parseDigests(hashData interface{}) []Digest {
	hashes, ok := hashData.(map[string]interface{})
	if !ok {
		return nil
	}
	var out []Digest
	for algo, hash := range hashes {
		if s, ok := hash.(string); ok {
			out = AddDigest(out, algo, s)
		}
	}
	SortDigests(out)
	return out
}
