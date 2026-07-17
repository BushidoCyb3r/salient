package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

func mustLoadSnap(t *testing.T, path string) graph.Snapshot {
	t.Helper()
	snap, err := snapshot.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func declaredFixturePaths(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, name := range []string{
		"ios-router.cfg", "unifi-networkconf.json",
		"unifi-firewallrule.json", "unifi-device.json",
	} {
		p, err := filepath.Abs(filepath.Join("..", "testdata", "netconfig", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing fixture %s: %v", p, err)
		}
		paths = append(paths, p)
	}
	return paths
}

func TestLoadDeclaredDiffsAndPersists(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snapPath := filepath.Join(dataDir, "snap.json.gz")
	writeSnapshot(t, snapPath, graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{
			// Behind the Gi0/0.40 declared gateway subnet (10.0.40.0/24).
			{IP: "10.0.40.10", Subnet: "10.0.40.0/24", MAC: "aa:bb:cc:dd:ee:02", FirstSeen: t0, LastSeen: t0, Scores: graph.ScoreSet{Composite: 0.9, Rank: 1}},
			// On a subnet no config declares.
			{IP: "10.9.9.9", Subnet: "10.9.9.0/24", FirstSeen: t0, LastSeen: t0, Scores: graph.ScoreSet{Composite: 0.5, Rank: 2}},
		},
	})

	model, err := a.LoadDeclared(snapPath, declaredFixturePaths(t))
	if err != nil {
		t.Fatal(err)
	}
	if model == nil {
		t.Fatal("nil model")
	}
	assertDeclaredSwitch := func(modelNodes []mapview.MapNode) {
		t.Helper()
		for _, n := range modelNodes {
			if n.ID == "10.0.40.10" {
				if n.Device != "Switch-24" || n.DeviceType != "usw" || n.Role != string(graph.RoleNetworkGear) || n.Tier != mapview.TierCore {
					t.Fatalf("UniFi switch overlay = %+v", n)
				}
				return
			}
		}
		t.Fatal("UniFi switch missing from map")
	}
	assertDeclaredSwitch(model.Nodes)

	// Findings summarize the diff.
	var summarized bool
	for _, f := range model.Findings {
		if len(f) > 0 && (contains(f, "device(s) declared") || contains(f, "undeclared CIDR")) {
			summarized = true
		}
	}
	if !summarized {
		t.Errorf("no device-config summary finding: %v", model.Findings)
	}

	// Persisted declared.json roundtrips and holds sanitized devices — never
	// raw config text (secrets).
	declaredJSON := filepath.Join(dataDir, "declared.json")
	raw, err := os.ReadFile(declaredJSON)
	if err != nil {
		t.Fatalf("declared.json not written: %v", err)
	}
	if contains(string(raw), "enable secret") || contains(string(raw), "snmp-server community") {
		t.Error("declared.json leaked raw config secrets")
	}
	art, err := a.loadDeclaredArtifact()
	if err != nil || art == nil {
		t.Fatalf("loadDeclaredArtifact: art=%v err=%v", art, err)
	}
	if len(art.Devices) != 2 { // IOS router + folded UniFi controller
		t.Errorf("persisted device count = %d, want 2", len(art.Devices))
	}
	// Reapply on a plain snapshot reload: LoadModel must re-derive the gateway
	// overlay from persisted configs (no error, gateway still resolves).
	reloaded, err := a.LoadModel(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	assertDeclaredSwitch(reloaded.Nodes)
	snap := mustLoadSnap(t, snapPath)
	if a.declaredGateways(snap)["10.0.40.1"] != "edge-rtr-01" {
		t.Error("declared gateway not reapplied on reload")
	}

	// Roundtrip JSON marshal of the artifact is stable.
	if _, err := json.Marshal(art); err != nil {
		t.Fatalf("artifact re-marshal: %v", err)
	}

	// Clearing removes persistence.
	if err := a.ClearDeclared(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(declaredJSON); !os.IsNotExist(err) {
		t.Errorf("declared.json survived ClearDeclared: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
