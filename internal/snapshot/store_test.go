package snapshot

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
)

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	snap := graph.Snapshot{
		Meta: graph.SnapshotMeta{
			CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			Window:    "336h", ClusterName: "test", Tool: "salient",
		},
		Nodes: []graph.Node{{IP: "10.0.1.10", Subnet: "10.0.1.0/24", Scores: graph.ScoreSet{Rank: 1, Composite: 0.9}}},
		Edges: []graph.Edge{{Src: "10.0.2.30", Dst: "10.0.1.10", Port: 88, Service: "kerberos", ConnCount: 100}},
	}
	path, err := Save(dir, snap)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("snapshot file mode = %v, want 0600", fi.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nodes[0].IP != "10.0.1.10" || got.Edges[0].Port != 88 || got.Meta.Window != "336h" {
		t.Errorf("round trip mismatch: %+v", got)
	}
	entries, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Nodes != 1 || entries[0].Edges != 1 {
		t.Errorf("bad index: %+v", entries)
	}
}

func TestLoadResolvesBareNameAgainstDefaultSnapshotsDir(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	created := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	path, err := Save(config.DataDirName, graph.Snapshot{Meta: graph.SnapshotMeta{CreatedAt: created}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Meta.CreatedAt.Equal(created) {
		t.Fatalf("created_at = %v, want %v", got.Meta.CreatedAt, created)
	}
}

func TestSaveSameTimestampDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	snap := graph.Snapshot{Meta: graph.SnapshotMeta{CreatedAt: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)}}
	first, err := Save(dir, snap)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Save(dir, snap)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("same-time saves used the same path")
	}
	entries, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(entries))
	}
}

func TestDecodeSnapshotRejectsTrailingJSON(t *testing.T) {
	_, err := decodeSnapshot([]byte(`{"meta":{},"nodes":[],"edges":[]} {"extra":true}`))
	if err == nil {
		t.Fatal("expected trailing JSON rejection")
	}
}

func TestLoadRejectsCorruptGzipTrailer(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write([]byte(`{"meta":{},"nodes":[],"edges":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	raw := compressed.Bytes()
	raw[len(raw)-1] ^= 0xff
	path := filepath.Join(t.TempDir(), "corrupt.json.gz")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected corrupt gzip trailer rejection")
	}
}

func TestLoadRejectsCompressedOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.json.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(config.SnapshotMaxCompressedBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected compressed-size rejection")
	}
}

func TestReadSnapshotRejectsDecompressedOversize(t *testing.T) {
	_, err := readSnapshot(strings.NewReader(`{"meta":{}}`), 4)
	if err == nil || !strings.Contains(err.Error(), "decompressed size") {
		t.Fatalf("want decompressed-size error, got %v", err)
	}
}
