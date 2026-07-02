package snapshot

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ArtifactEntry groups locally stored artifacts from one scan.
type ArtifactEntry struct {
	Timestamp string
	Report    string
	Map       string
	Snapshot  string
}

// ScanArtifacts lists stored reports, maps, and snapshots newest first.
func ScanArtifacts(dataDir string) ([]ArtifactEntry, error) {
	entries := map[string]*ArtifactEntry{}
	for _, artifact := range []struct {
		dir, suffix string
		set         func(*ArtifactEntry, string)
	}{
		{"reports", ".html", func(entry *ArtifactEntry, path string) { entry.Report = path }},
		{"maps", ".html", func(entry *ArtifactEntry, path string) { entry.Map = path }},
		{"snapshots", ".json.gz", func(entry *ArtifactEntry, path string) { entry.Snapshot = path }},
	} {
		files, err := os.ReadDir(filepath.Join(dataDir, artifact.dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), artifact.suffix) {
				continue
			}
			stamp := strings.TrimSuffix(file.Name(), artifact.suffix)
			entry := entries[stamp]
			if entry == nil {
				entry = &ArtifactEntry{Timestamp: stamp}
				entries[stamp] = entry
			}
			artifact.set(entry, filepath.ToSlash(filepath.Join(artifact.dir, file.Name())))
		}
	}

	ordered := make([]ArtifactEntry, 0, len(entries))
	for _, entry := range entries {
		ordered = append(ordered, *entry)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Timestamp > ordered[j].Timestamp })
	return ordered, nil
}
