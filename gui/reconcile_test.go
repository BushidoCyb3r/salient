package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func TestLoadReconcileModelFlagsUndocumentedAndWarns(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	snapPath := filepath.Join(dataDir, "snap.json.gz")
	writeSnapshot(t, snapPath, graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{
			{IP: "10.0.0.1", Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0, Scores: graph.ScoreSet{Composite: 0.9, Rank: 1}},
			{IP: "10.0.0.2", Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0, Scores: graph.ScoreSet{Composite: 0.8, Rank: 2}},
		},
	})
	csvPath := filepath.Join(dataDir, "assets.csv")
	// 10.0.0.1 documented; 10.0.0.2 observed-undocumented; bad row -> warning.
	if err := os.WriteFile(csvPath, []byte("ip,hostname,role\n10.0.0.1,dc01,DomainController\nnot-an-ip,bad,host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := a.LoadReconcileModel(snapPath, csvPath)
	if err != nil {
		t.Fatal(err)
	}
	var flagged bool
	for _, n := range m.Nodes {
		if n.ID == "10.0.0.2" && n.Drift == "undocumented" {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("undocumented host not flagged: %+v", m.Nodes)
	}
	var warned, counted bool
	for _, f := range m.Findings {
		if strings.Contains(f, "asset list:") {
			warned = true
		}
		if strings.Contains(f, "not in the asset list") {
			counted = true
		}
	}
	if !warned || !counted {
		t.Errorf("findings missing warning/count: %v", m.Findings)
	}
}

// The manual-grid path (LoadReconcileModelCSV) must reach the same result as a
// CSV file — it feeds the identical parse+reconcile core from typed-in text.
func TestLoadReconcileModelCSVMatchesFile(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	snapPath := filepath.Join(dataDir, "snap.json.gz")
	writeSnapshot(t, snapPath, graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{
			{IP: "10.0.0.1", Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0, Scores: graph.ScoreSet{Composite: 0.9, Rank: 1}},
			{IP: "10.0.0.2", Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0, Scores: graph.ScoreSet{Composite: 0.8, Rank: 2}},
		},
	})
	// Same rows the in-app grid serializes: header + one documented host.
	m, err := a.LoadReconcileModelCSV(snapPath, "ip,hostname,role,segment\n10.0.0.1,dc01,DomainController,srv\n")
	if err != nil {
		t.Fatal(err)
	}
	var flagged bool
	for _, n := range m.Nodes {
		if n.ID == "10.0.0.2" && n.Drift == "undocumented" {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("undocumented host not flagged from manual CSV: %+v", m.Nodes)
	}
}

func TestPickAssetCSVCancel(t *testing.T) {
	a := &App{openFileFn: func(opts runtime.OpenDialogOptions) (string, error) { return "", nil }}
	got, err := a.PickAssetCSV()
	if err != nil || got != "" {
		t.Fatalf("cancel = (%q, %v), want empty no error", got, err)
	}
}
