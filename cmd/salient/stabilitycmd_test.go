package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
	"github.com/BushidoCyb3r/salient/internal/stability"
)

func TestStabilityCommandWritesJSON(t *testing.T) {
	dataDir := t.TempDir()
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	for i, ranks := range [][2]int{{1, 2}, {1, 2}, {2, 1}} {
		nodes := []graph.Node{
			{IP: "10.0.0.1", Scores: graph.ScoreSet{Rank: ranks[0]}},
			{IP: "10.0.0.2", Scores: graph.ScoreSet{Rank: ranks[1]}},
		}
		if _, err := snapshot.Save(dataDir, graph.Snapshot{
			Meta:  graph.SnapshotMeta{CreatedAt: t0.Add(time.Duration(i) * 24 * time.Hour)},
			Nodes: nodes,
		}); err != nil {
			t.Fatal(err)
		}
	}

	cmd := newStabilityCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--data-dir", dataDir, "--format", "json", "--top", "1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got []stability.NodeStability
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if len(got) != 2 {
		t.Fatalf("want 2 nodes, got %+v", got)
	}
	for _, s := range got {
		if s.Occurrences != 3 || s.Classification != stability.ClassPersistent {
			t.Errorf("bad stats for %s: %+v", s.IP, s)
		}
	}
}

func TestStabilityCommandErrorsOnEmptyDataDir(t *testing.T) {
	cmd := newStabilityCmd()
	cmd.SetArgs([]string{"--data-dir", t.TempDir()})
	if err := cmd.Execute(); err == nil {
		t.Error("want error for a data dir with no stored snapshots")
	}
}
