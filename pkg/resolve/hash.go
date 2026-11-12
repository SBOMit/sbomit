package resolve

import (
	"context"
	"fmt"
	"path"
	"sort"
	"time"

	"github.com/sbomit/sbomit/pkg/hashlookup"
	"github.com/sbomit/sbomit/pkg/resolver"
)

// defaultHashLookupTimeout bounds Options.HashLookup when no timeout is set.
const defaultHashLookupTimeout = 60 * time.Second

// hashedPackage is an OS package found by hash lookup, with the attested
// paths assigned to it.
type hashedPackage struct {
	info    resolver.PackageInfo
	matches []hashMatch
}

type hashMatch struct {
	path   string // as attested (may differ from the cleaned path sent)
	source Source
}

// attributeByHash sends the unclaimed system files to opts.HashLookup and
// claims the ones it attributes. It returns the packages found, the files
// still unclaimed and any warnings. If the lookup fails, nothing is claimed
// and resolution carries on with a warning.
func attributeByHash(opts Options, unclaimed []resolver.FileInfo) ([]hashedPackage, []resolver.FileInfo, []string) {
	// The service sees cleaned paths; remember every attested spelling.
	attested := map[string][]string{}
	var send []hashlookup.File
	for _, f := range unclaimed {
		var shas []string
		for _, d := range f.Digests {
			if d.Algorithm == "sha256" {
				shas = append(shas, d.Value)
			}
		}
		c, ok := hashlookup.Candidate(f.Path, shas)
		if !ok {
			continue
		}
		if _, dup := attested[c.Path]; !dup {
			send = append(send, c)
		}
		attested[c.Path] = append(attested[c.Path], f.Path)
	}
	if len(send) == 0 {
		return nil, unclaimed, nil
	}

	timeout := opts.HashLookupTimeout
	if timeout <= 0 {
		timeout = defaultHashLookupTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := opts.HashLookup.Attribute(ctx, send)
	if err != nil {
		return nil, unclaimed, []string{fmt.Sprintf("hash lookup failed, %d system files left unclaimed: %v", len(send), err)}
	}

	claimed := map[string]bool{}
	var out []hashedPackage
	for _, p := range res.Packages {
		if p.PURL == "" {
			continue
		}
		hp := hashedPackage{info: resolver.PackageInfo{
			Name: p.Name, Version: p.Version(), Ecosystem: "deb", PURL: p.PURL, PkgMgr: "dpkg",
		}}
		for _, m := range p.Files {
			// Only claim paths we sent: never trust the service to name others.
			for _, orig := range attested[path.Clean(m.Path)] {
				if claimed[orig] {
					continue
				}
				claimed[orig] = true
				src := SourceHash
				if m.Evidence == hashlookup.EvidencePycSource {
					// The .pyc itself is matched by its path, via the .py
					// source the package ships.
					src = SourcePath
				}
				hp.matches = append(hp.matches, hashMatch{path: orig, source: src})
			}
		}
		if len(hp.matches) == 0 {
			continue
		}
		sort.Slice(hp.matches, func(i, j int) bool { return hp.matches[i].path < hp.matches[j].path })
		out = append(out, hp)
	}

	var remaining []resolver.FileInfo
	for _, f := range unclaimed {
		if !claimed[f.Path] {
			remaining = append(remaining, f)
		}
	}
	return out, remaining, nil
}
