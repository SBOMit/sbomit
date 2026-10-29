package attestation

// CommandRunExtractor extracts files from command-run attestations
// Command-run attestations contain files that were opened/accessed during command execution
type CommandRunExtractor struct{}

func NewCommandRunExtractor() *CommandRunExtractor {
	return &CommandRunExtractor{}
}

func (e *CommandRunExtractor) Name() string {
	return "command-run"
}

func (e *CommandRunExtractor) Extract(data map[string]interface{}) []FileInfo {
	processesRaw, ok := data["processes"].([]interface{})
	if !ok {
		return nil
	}

	// A path opened by several processes is recorded once per process, maybe
	// empty in one and not empty in another, so every distinct digest is kept.
	var order []string
	byPath := make(map[string]*FileInfo)
	for _, procRaw := range processesRaw {
		proc, ok := procRaw.(map[string]interface{})
		if !ok {
			continue
		}
		opened, ok := proc["openedfiles"].(map[string]interface{})
		if !ok {
			continue
		}
		for path, hashData := range opened {
			fi, seen := byPath[path]
			if !seen {
				fi = &FileInfo{Path: path}
				byPath[path] = fi
				order = append(order, path)
			}
			// Kept with or without a digest: identity comes from the path.
			fi.Digests = MergeDigests(fi.Digests, parseDigests(hashData))
		}
	}

	files := make([]FileInfo, 0, len(order))
	for _, path := range order {
		fi := byPath[path]
		SortDigests(fi.Digests)
		files = append(files, *fi)
	}
	return files
}
