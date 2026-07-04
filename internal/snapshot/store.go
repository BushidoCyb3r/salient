// Package snapshot persists and lists Snapshots as gzipped JSON. No database:
// one file per run under defilade-data/snapshots plus an index.json. Files are
// written 0600 in 0700 dirs — topology artifacts are sensitive (§14).
package snapshot

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/safefile"
)

// IndexEntry is one line of index.json summarizing a stored snapshot.
type IndexEntry struct {
	File      string    `json:"file"`
	CreatedAt time.Time `json:"created_at"`
	Window    string    `json:"window"`
	Nodes     int       `json:"nodes"`
	Edges     int       `json:"edges"`
	Cluster   string    `json:"cluster"`
}

// SnapshotsDir returns the snapshots directory under the data root.
func SnapshotsDir(dataRoot string) string { return filepath.Join(dataRoot, "snapshots") }

// Save writes the snapshot as <timestamp>.json.gz and appends to index.json.
// Returns the file path.
func Save(dataRoot string, snap graph.Snapshot) (string, error) {
	dir := SnapshotsDir(dataRoot)
	name := snap.Meta.CreatedAt.UTC().Format("20060102T150405Z") + ".json.gz"
	path := filepath.Join(dir, name)

	if err := safefile.Write(path, func(w io.Writer) error {
		gz := gzip.NewWriter(w)
		enc := json.NewEncoder(gz)
		enc.SetIndent("", " ")
		if err := enc.Encode(snap); err != nil {
			_ = gz.Close()
			return fmt.Errorf("writing snapshot: %w", err)
		}
		return gz.Close()
	}); err != nil {
		return "", err
	}
	if err := appendIndex(dir, IndexEntry{
		File:      name,
		CreatedAt: snap.Meta.CreatedAt,
		Window:    snap.Meta.Window,
		Nodes:     len(snap.Nodes),
		Edges:     len(snap.Edges),
		Cluster:   snap.Meta.ClusterName,
	}); err != nil {
		return "", err
	}
	return path, nil
}

// Load reads a snapshot from a .json.gz file path (or a bare name resolved
// against the snapshots dir).
func Load(path string) (graph.Snapshot, error) {
	var snap graph.Snapshot
	f, err := os.Open(path)
	if os.IsNotExist(err) && !filepath.IsAbs(path) && filepath.Base(path) == path {
		f, err = os.Open(filepath.Join(config.DataDirName, "snapshots", path))
	}
	if err != nil {
		return snap, fmt.Errorf("opening snapshot: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return snap, fmt.Errorf("reading gzip: %w", err)
	}
	defer gz.Close()
	if err := json.NewDecoder(gz).Decode(&snap); err != nil {
		return snap, fmt.Errorf("decoding snapshot: %w", err)
	}
	return snap, nil
}

// List returns index entries, newest first.
func List(dataRoot string) ([]IndexEntry, error) {
	entries, err := readIndex(SnapshotsDir(dataRoot))
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CreatedAt.After(entries[j].CreatedAt) })
	return entries, nil
}

func indexPath(dir string) string { return filepath.Join(dir, "index.json") }

func readIndex(dir string) ([]IndexEntry, error) {
	raw, err := os.ReadFile(indexPath(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading index: %w", err)
	}
	var entries []IndexEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parsing index: %w", err)
	}
	return entries, nil
}

func appendIndex(dir string, e IndexEntry) error {
	entries, err := readIndex(dir)
	if err != nil {
		return err
	}
	entries = append(entries, e)
	raw, err := json.MarshalIndent(entries, "", " ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(indexPath(dir), raw)
}
