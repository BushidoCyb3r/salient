package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

// saveDeclaredSnapshot builds a deterministic snapshot with one host behind a
// declared gateway subnet (10.0.40.0/24 → Gi0/0.40 on edge-rtr-01) and one
// host on a subnet no config declares (10.9.9.0/24, undeclared CIDR).
func saveDeclaredSnapshot(t *testing.T) string {
	t.Helper()
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	path, err := snapshot.Save(t.TempDir(), graph.Snapshot{
		Meta: graph.SnapshotMeta{CreatedAt: t0},
		Nodes: []graph.Node{
			{IP: "10.0.40.10", Subnet: "10.0.40.0/24", FirstSeen: t0, LastSeen: t0},
			{IP: "10.9.9.9", Subnet: "10.9.9.0/24", FirstSeen: t0, LastSeen: t0},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDeclaredCommandGoldenJSON(t *testing.T) {
	snapPath := saveDeclaredSnapshot(t)
	configs := filepath.Join("..", "..", "testdata", "netconfig", "ios-router.cfg") + "," +
		filepath.Join("..", "..", "testdata", "netconfig", "unifi-networkconf.json") + "," +
		filepath.Join("..", "..", "testdata", "netconfig", "unifi-firewallrule.json") + "," +
		filepath.Join("..", "..", "testdata", "netconfig", "unifi-device.json")

	cmd := newDeclaredCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", snapPath, "--configs", configs})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "declared.golden.json")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, stdout.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Errorf("output mismatch (run with -update to refresh):\n--- got ---\n%s\n--- want ---\n%s", stdout.String(), want)
	}
}

func TestDeclaredCommandRequiresFlags(t *testing.T) {
	cmd := newDeclaredCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", "x.json.gz"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("want error when --configs missing")
	}
}
