package generator

import (
	"sort"

	"github.com/sbomit/sbomit/pkg/resolve"
)

// The CLI's processing rules decide which packages from a resolve.Result go in
// the SBOM. A rule is set per ecosystem and package manager and says which
// evidence it includes. By default only install paths are included; network
// requests are additional provenance. npm is the exception: its install paths
// carry no version, so an artifact it downloaded is included too.

// ruleKey is what a rule is looked up by.
type ruleKey struct {
	ecosystem string
	pkgMgr    string
}

// rule says which evidence from one package manager puts a package in the SBOM.
type rule struct {
	includePaths     bool
	includeDownloads bool
}

// defaultRule applies to every pair not in rules. Here we define the default
// behavior: only include path evidence, not network requests.
// As package managers fetch more than they install.
var defaultRule = rule{includePaths: true}

// rules overrides defaultRule. To handle a new package manager, add its pair.
var rules = map[ruleKey]rule{
	{ecosystem: "npm", pkgMgr: "npm"}: {includePaths: true, includeDownloads: true},
}

func lookupRule(ecosystem, pkgMgr string) rule {
	if r, ok := rules[ruleKey{ecosystem, pkgMgr}]; ok {
		return r
	}
	return defaultRule
}

// shouldInclude reports whether any of a package's evidence is included by
// the rule for the package manager that produced it.
func shouldInclude(pkg resolve.Package) bool {
	for _, e := range pkg.Evidence {
		r := lookupRule(pkg.Ecosystem, e.PkgMgr)
		switch {
		case e.Source == resolve.SourcePath && r.includePaths:
			return true
		case e.Source == resolve.SourceNetwork && r.includeDownloads && e.Artifact:
			// A download counts only if it is the artifact.
			return true
		}
	}
	return false
}

// applyRules keeps the packages that should be included. An excluded package's
// files move in the result, as unclaimed.
func applyRules(result *resolve.Result) *resolve.Result {
	out := *result
	out.Packages = nil
	out.Files = append([]resolve.File(nil), result.Files...)

	for _, pkg := range result.Packages {
		if shouldInclude(pkg) {
			out.Packages = append(out.Packages, pkg)
			continue
		}
		out.Files = append(out.Files, pkg.Files...)
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })

	return &out
}
