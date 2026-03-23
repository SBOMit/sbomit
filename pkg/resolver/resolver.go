package resolver

type PackageInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Ecosystem   string            `json:"ecosystem"` // pypi, golang, cargo, npm, etc.
	PURL        string            `json:"purl"`
	Licenses    []string          `json:"licenses,omitempty"`
	Hashes      map[string]string `json:"hashes,omitempty"`
	FoundBy     string            `json:"found_by"` // which resolver found this
	DownloadURL string            `json:"download_url,omitempty"` // set by network resolvers
	DownloadIP  string            `json:"download_ip,omitempty"`  // set by network resolvers
}

type FileInfo struct {
	Path   string            `json:"path"`
	Hashes map[string]string `json:"hashes,omitempty"`
}

type ResolverResult struct {
	Packages []PackageInfo `json:"packages"`
	Files    []FileInfo    `json:"files"`
}

type Resolver interface {
	// Name returns the name of this resolver (e.g., "python", "go", "rust")
	Name() string

	// Resolve takes a list of file paths with hashes and returns:
	// - packages: successfully resolved packages
	// - remainingFiles: files that this resolver couldn't resolve (passed to next resolver)
	Resolve(files []FileInfo) (packages []PackageInfo, remainingFiles []FileInfo)
}

type ResolverChain struct {
	resolvers []Resolver
	filter    *FileFilter
}

// NewResolverChain creates a new resolver chain with default resolvers
func NewResolverChain() *ResolverChain {
	return &ResolverChain{
		resolvers: []Resolver{
			NewPythonResolver(),
			// Add more resolvers here as they are implemented:
			NewGoResolver(),
			NewRustResolver(),
			NewJavaScriptResolver(),
		},
		filter: NewFileFilter(),
	}
}

func (c *ResolverChain) AddResolver(r Resolver) {
	c.resolvers = append(c.resolvers, r)
}

// ResolveAll processes all files through the resolver chain
// 1. Filter out unwanted files (cache, temp, system files)
// 2. Pass files through each resolver in sequence
// 3. Each resolver extracts packages it recognizes and passes remaining files to next
// 4. Filter out files that belong to resolved packages (e.g., werkzeug/routing/rules.py if werkzeug is resolved)
// 5. Files that no resolver can handle end up as unresolved files in the result
func (c *ResolverChain) ResolveAll(files []FileInfo) ResolverResult {
	result := ResolverResult{
		Packages: []PackageInfo{},
		Files:    []FileInfo{},
	}

	// Step 1: Filter files first
	var filteredFiles []FileInfo
	for _, f := range files {
		if c.filter.ShouldInclude(f.Path) {
			filteredFiles = append(filteredFiles, f)
		}
	}

	// Step 2: Pass through resolver chain
	remainingFiles := filteredFiles
	seenPackages := make(map[string]bool)

	for _, resolver := range c.resolvers {
		packages, notResolved := resolver.Resolve(remainingFiles)

		for _, pkg := range packages {
			if !seenPackages[pkg.PURL] {
				seenPackages[pkg.PURL] = true
				result.Packages = append(result.Packages, pkg)
			}
		}

		// Pass remaining files to next resolver
		remainingFiles = notResolved
	}

	// Step 3: Filter out files that belong to resolved packages
	remainingFiles = c.filterPackageFiles(remainingFiles, result.Packages)

	// Step 4: Files that couldn't be resolved by any resolver
	result.Files = remainingFiles

	return result
}

// filterPackageFiles removes files that belong to resolved packages
// For example, if werkzeug is resolved, filter out werkzeug/routing/rules.py
func (c *ResolverChain) filterPackageFiles(files []FileInfo, packages []PackageInfo) []FileInfo {
	if len(packages) == 0 {
		return files
	}

	// Build package prefix filters from resolved packages
	// Each resolver type knows its own naming conventions
	packageFilters := make([]PackageFileFilter, 0, len(c.resolvers))
	for _, resolver := range c.resolvers {
		if pff, ok := resolver.(PackageFileFilterer); ok {
			packageFilters = append(packageFilters, pff.CreateFileFilters(packages)...)
		}
	}

	if len(packageFilters) == 0 {
		return files
	}

	var result []FileInfo
	for _, f := range files {
		belongsToPackage := false
		for _, filter := range packageFilters {
			if filter.Matches(f.Path) {
				belongsToPackage = true
				break
			}
		}
		if !belongsToPackage {
			result = append(result, f)
		}
	}

	return result
}

type PackageFileFilter interface {
	Matches(path string) bool
}

// PackageFileFilterer is implemented by resolvers that can filter package files
type PackageFileFilterer interface {
	CreateFileFilters(packages []PackageInfo) []PackageFileFilter
}
