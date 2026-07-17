// Package snapshot persists and lists Snapshots as gzipped JSON. No database:
// one immutable file per run under salient-data/snapshots. Files are
// written 0600 in 0700 dirs — topology artifacts are sensitive (§14).
package snapshot

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/safefile"
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

// Save writes the snapshot as <timestamp>.json.gz.
// Returns the file path.
func Save(dataRoot string, snap graph.Snapshot) (string, error) {
	dir := SnapshotsDir(dataRoot)
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("creating snapshot name: %w", err)
	}
	name := snap.Meta.CreatedAt.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(nonce[:]) + ".json.gz"
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
	defer func() { _ = f.Close() }()
	if info, statErr := f.Stat(); statErr != nil {
		return snap, fmt.Errorf("stating snapshot: %w", statErr)
	} else if info.Size() > config.SnapshotMaxCompressedBytes {
		return snap, fmt.Errorf("snapshot compressed size exceeds %d bytes", config.SnapshotMaxCompressedBytes)
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return snap, fmt.Errorf("reading gzip: %w", err)
	}
	snap, err = readSnapshot(gz, config.SnapshotMaxDecompressedBytes)
	closeErr := gz.Close()
	if err != nil {
		return snap, err
	}
	if closeErr != nil {
		return snap, fmt.Errorf("reading gzip trailer: %w", closeErr)
	}
	return snap, nil
}

func readSnapshot(r io.Reader, limit int64) (graph.Snapshot, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return graph.Snapshot{}, fmt.Errorf("reading snapshot: %w", err)
	}
	if int64(len(raw)) > limit {
		return graph.Snapshot{}, fmt.Errorf("snapshot decompressed size exceeds %d bytes", limit)
	}
	return decodeSnapshot(raw)
}

func decodeSnapshot(raw []byte) (graph.Snapshot, error) {
	var snap graph.Snapshot
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&snap); err != nil {
		return snap, fmt.Errorf("decoding snapshot: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return snap, fmt.Errorf("decoding snapshot: trailing JSON value")
		}
		return snap, fmt.Errorf("decoding snapshot trailer: %w", err)
	}
	return snap, nil
}

// List derives entries from immutable snapshot files, avoiding a shared index
// read-modify-write race when multiple processes save concurrently.
func List(dataRoot string) ([]IndexEntry, error) {
	dir := SnapshotsDir(dataRoot)
	files, err := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	if err != nil {
		return nil, err
	}
	entries := make([]IndexEntry, 0, len(files))
	for _, path := range files {
		snap, err := Load(path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, IndexEntry{
			File: filepath.Base(path), CreatedAt: snap.Meta.CreatedAt,
			Window: snap.Meta.Window, Nodes: len(snap.Nodes), Edges: len(snap.Edges),
			Cluster: snap.Meta.ClusterName,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CreatedAt.After(entries[j].CreatedAt) })
	return entries, nil
}
