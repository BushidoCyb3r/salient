package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/mission"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

func saveMissionSnapshot(t *testing.T) string {
	t.Helper()
	path, err := snapshot.Save(t.TempDir(), graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
		Nodes: []graph.Node{
			{IP: "10.0.1.1"}, {IP: "10.0.1.2"}, {IP: "10.0.9.9"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.1.2", Dst: "10.0.1.1", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMissionCommandWritesJSON(t *testing.T) {
	path := saveMissionSnapshot(t)
	cmd := newMissionCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--snapshot", path, "--scope", "10.0.1.1", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got []mission.Score
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if len(got) != 2 {
		t.Fatalf("want 2 scored hosts (scope + 1 hop), got %+v", got)
	}
	for _, s := range got {
		if s.IP == "10.0.9.9" {
			t.Errorf("unrelated host must not appear: %+v", got)
		}
	}
}

func TestMissionCommandRequiresScope(t *testing.T) {
	cmd := newMissionCmd()
	cmd.SetArgs([]string{"--snapshot", filepath.Join(t.TempDir(), "x.json.gz")})
	if err := cmd.Execute(); err == nil {
		t.Error("want error when --scope is missing")
	}
}

func TestMissionCommandErrorsWhenScopeNotInSnapshot(t *testing.T) {
	path := saveMissionSnapshot(t)
	cmd := newMissionCmd()
	cmd.SetArgs([]string{"--snapshot", path, "--scope", "10.0.99.99"})
	if err := cmd.Execute(); err == nil {
		t.Error("want error when no scope IP exists in the snapshot")
	}
}
