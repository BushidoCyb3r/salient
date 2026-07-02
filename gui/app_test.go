package main

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func TestListSnapshotsFindsReportArtifact(t *testing.T) {
	dataDir := t.TempDir()
	reports := filepath.Join(dataDir, "reports")
	if err := os.Mkdir(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reports, "20260702T120000Z.html"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := (&App{DataDir: dataDir}).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Timestamp != "20260702T120000Z" {
		t.Fatalf("ListSnapshots() = %#v", got)
	}
}

func TestLoadModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json.gz")
	snap := graph.Snapshot{
		Meta: graph.SnapshotMeta{ClusterName: "test-cluster"},
		Nodes: []graph.Node{{
			IP: "10.0.0.10", Subnet: "10.0.0.0/24",
			Roles:  []graph.RoleAssertion{{Role: graph.RoleWebServer}},
			Scores: graph.ScoreSet{Composite: 1, Rank: 1},
		}},
	}
	writeSnapshot(t, path, snap)

	got, err := (&App{}).LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Meta.ClusterName != "test-cluster" || len(got.Nodes) != 1 {
		t.Fatalf("LoadModel() = %#v", got)
	}
}

func TestLoadModelMissingSnapshot(t *testing.T) {
	if _, err := (&App{}).LoadModel(filepath.Join(t.TempDir(), "missing.json.gz")); err == nil {
		t.Fatal("LoadModel() error = nil")
	}
}

func TestLegend(t *testing.T) {
	got := (&App{}).Legend()
	if len(got) != 7 {
		t.Fatalf("Legend() has %d items, want 7", len(got))
	}
	if got[0].Label != config.ClassLabel(config.ClassAuth) || got[0].Color == "" {
		t.Fatalf("Legend()[0] = %#v", got[0])
	}
}

func writeSnapshot(t *testing.T, path string, snap graph.Snapshot) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode(snap); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
