package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func TestLoadDriftModelMarksAppearedAndCounts(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	node := func(ip string, rank int) graph.Node {
		return graph.Node{IP: ip, Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0,
			Scores: graph.ScoreSet{Composite: 0.9, Rank: rank}}
	}
	fromPath := filepath.Join(dataDir, "from.json.gz")
	toPath := filepath.Join(dataDir, "to.json.gz")
	writeSnapshot(t, fromPath, graph.Snapshot{
		Meta:  graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{node("10.0.0.1", 1)},
	})
	writeSnapshot(t, toPath, graph.Snapshot{
		Meta:  graph.SnapshotMeta{CreatedAt: t0.Add(24 * time.Hour)},
		Nodes: []graph.Node{node("10.0.0.1", 1), node("10.0.0.2", 2)},
	})
	m, err := a.LoadDriftModel(fromPath, toPath)
	if err != nil {
		t.Fatal(err)
	}
	var newDrift bool
	for _, n := range m.Nodes {
		if n.ID == "10.0.0.2" && n.Drift == "new" {
			newDrift = true
		}
	}
	if !newDrift {
		t.Errorf("appeared node not marked drift=new: %+v", m.Nodes)
	}
	var counts bool
	for _, f := range m.Findings {
		if strings.Contains(f, "1 appeared") {
			counts = true
		}
	}
	if !counts {
		t.Errorf("drift counts finding missing: %v", m.Findings)
	}
	// Device overlay must apply to drift models too.
	if _, err := a.AssignIP("router", "10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	m, err = a.LoadDriftModel(fromPath, toPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range m.Nodes {
		if n.ID == "10.0.0.2" && n.Device != "router" {
			t.Errorf("device overlay missing on drift model: %+v", n)
		}
	}
}

func TestLoadDriftModelFindsNewProvider(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	node := func(ip string, rank int) graph.Node {
		return graph.Node{IP: ip, Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0,
			Scores: graph.ScoreSet{Composite: 0.9, Rank: rank}}
	}
	fromPath := filepath.Join(dataDir, "from.json.gz")
	toPath := filepath.Join(dataDir, "to.json.gz")
	writeSnapshot(t, fromPath, graph.Snapshot{
		Meta:  graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{node("10.0.0.1", 1)},
	})
	writeSnapshot(t, toPath, graph.Snapshot{
		Meta:  graph.SnapshotMeta{CreatedAt: t0.Add(24 * time.Hour)},
		Nodes: []graph.Node{node("10.0.0.1", 1), node("10.0.0.99", 40)},
		Edges: []graph.Edge{
			{Src: "10.0.0.1", Dst: "10.0.0.99", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	})
	m, err := a.LoadDriftModel(fromPath, toPath)
	if err != nil {
		t.Fatal(err)
	}
	var foundProvider bool
	for _, f := range m.Findings {
		if strings.Contains(f, "10.0.0.99") && strings.Contains(f, "dns") {
			foundProvider = true
		}
	}
	if !foundProvider {
		t.Errorf("new provider finding missing: %v", m.Findings)
	}
	var foundSummary bool
	for _, f := range m.Findings {
		if strings.Contains(f, "1 new sensitive-service provider") {
			foundSummary = true
		}
	}
	if !foundSummary {
		t.Errorf("new provider count missing from summary finding: %v", m.Findings)
	}
}

func TestLoadDriftModelFindsProviderDisplacement(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	node := func(ip string, rank int) graph.Node {
		return graph.Node{IP: ip, Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0,
			Scores: graph.ScoreSet{Composite: 0.9, Rank: rank}}
	}
	fromPath := filepath.Join(dataDir, "from.json.gz")
	toPath := filepath.Join(dataDir, "to.json.gz")
	writeSnapshot(t, fromPath, graph.Snapshot{
		Meta:  graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{node("10.0.0.10", 5), node("10.0.0.20", 6), node("10.0.1.1", 0)},
		Edges: []graph.Edge{
			{Src: "10.0.1.1", Dst: "10.0.0.20", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	})
	writeSnapshot(t, toPath, graph.Snapshot{
		Meta:  graph.SnapshotMeta{CreatedAt: t0.Add(24 * time.Hour)},
		Nodes: []graph.Node{node("10.0.0.10", 5), node("10.0.0.20", 6), node("10.0.1.1", 0)},
		Edges: []graph.Edge{
			{Src: "10.0.1.1", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	})
	m, err := a.LoadDriftModel(fromPath, toPath)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range m.Findings {
		if strings.Contains(f, "10.0.0.20:53") && strings.Contains(f, "10.0.0.10:53") {
			found = true
		}
	}
	if !found {
		t.Errorf("provider displacement finding missing: %v", m.Findings)
	}
}
