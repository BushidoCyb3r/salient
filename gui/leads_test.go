package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func TestLoadHuntLeadsCurrentOnly(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(dataDir, "snap.json.gz")
	writeSnapshot(t, path, graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Subnet: "10.0.1.0/24"},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				FirstSeen: t0, LastSeen: t0},
		},
	})
	leads, err := a.LoadHuntLeads(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 1 || leads[0].IP != "10.0.1.11" || leads[0].Reason != "sole-provider" {
		t.Fatalf("bad leads: %+v", leads)
	}
}

func TestLoadHuntLeadsWithBaseAndAssets(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	fromPath := filepath.Join(dataDir, "from.json.gz")
	toPath := filepath.Join(dataDir, "to.json.gz")
	writeSnapshot(t, fromPath, graph.Snapshot{Meta: graph.SnapshotMeta{CreatedAt: t0}})
	writeSnapshot(t, toPath, graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: t0.Add(24 * time.Hour)},
		Nodes: []graph.Node{
			{IP: "10.0.1.99", Subnet: "10.0.1.0/24"},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.99", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				FirstSeen: t0.Add(24 * time.Hour), LastSeen: t0.Add(24 * time.Hour)},
		},
	})
	assetsPath := filepath.Join(dataDir, "assets.csv")
	if err := os.WriteFile(assetsPath, []byte("ip,hostname,role\n10.0.1.50,other.corp,web server\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	leads, err := a.LoadHuntLeads(toPath, fromPath, assetsPath)
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.1.99 is both a new provider (absent from the baseline, so
	// NewHost=true) AND undocumented (absent from assets.csv, which only
	// lists 10.0.1.50). reasonPriority ranks undocumented (1) above
	// new-provider (2), so the deduplicated lead must report "undocumented".
	if len(leads) != 1 || leads[0].IP != "10.0.1.99" || leads[0].Reason != "undocumented" {
		t.Fatalf("bad leads (want exactly 1 lead for 10.0.1.99 with Reason=undocumented, since undocumented outranks new-provider): %+v", leads)
	}
}
