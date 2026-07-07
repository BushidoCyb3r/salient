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
