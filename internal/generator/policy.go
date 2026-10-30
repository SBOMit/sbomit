package generator

import "github.com/sbomit/sbomit/pkg/resolve"

// The CLI's package policy. A path shows a package was installed; a download
// alone does not, since package managers fetch more than they install. So
// download-only packages are listed only where no path could show them.

// networkOnlyIsAuthoritative lists (ecosystem, package manager) pairs whose
// install paths never show a version, so a download is the only evidence.
// (Ex: npm) Every other package manager's paths include the version, so
// a download with no matching path was fetched, not installed.
var networkOnlyIsAuthoritative = map[[2]string]bool{
	{"npm", "npm"}: true,
}

func selectPackages(result *resolve.Result) *resolve.Result {
	out := *result
	out.Packages = nil

	kept := make(map[string]struct{}, len(result.Packages))
	for _, pkg := range result.Packages {
		if !reportPackage(pkg) {
			continue
		}
		out.Packages = append(out.Packages, pkg)
		kept[pkg.ID] = struct{}{}
	}

	out.Relationships = nil
	for _, rel := range result.Relationships {
		if _, ok := kept[rel.FromPackageID]; ok {
			out.Relationships = append(out.Relationships, rel)
		}
	}

	return &out
}

func reportPackage(pkg resolve.Package) bool {
	for _, e := range pkg.Evidence {
		if e.Source == resolve.SourcePath {
			return true
		}
	}
	for _, e := range pkg.Evidence {
		if e.Source == resolve.SourceNetwork && e.Artifact &&
			networkOnlyIsAuthoritative[[2]string{pkg.Ecosystem, e.PkgMgr}] {
			return true
		}
	}
	return false
}
