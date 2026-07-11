package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func TestLoadServiceAuthority(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(dataDir, "snap.json.gz")
	writeSnapshot(t, path, graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Hostnames: []string{"dns1.corp"},
				Roles: []graph.RoleAssertion{{Role: graph.RoleDNS, Confidence: 0.9}}},
			{IP: "10.0.3.30"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				FirstSeen: t0, LastSeen: t0},
		},
	})
	rows, err := a.LoadServiceAuthority(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].IP != "10.0.1.11" || rows[0].Service != "dns" || rows[0].Clients != 1 {
		t.Fatalf("bad rows: %+v", rows)
	}
}

func TestLoadServiceAuthorityMissingSnapshot(t *testing.T) {
	a := &App{DataDir: t.TempDir()}
	if _, err := a.LoadServiceAuthority("does-not-exist.json.gz"); err == nil {
		t.Error("want error for missing snapshot, got nil")
	}
}
