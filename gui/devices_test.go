package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/devices"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func TestRegistryBindingsRoundTrip(t *testing.T) {
	a := &App{DataDir: t.TempDir()}
	if moved, err := a.AssignIP("router", "10.0.0.1"); err != nil || moved != "" {
		t.Fatalf("AssignIP = (%q, %v)", moved, err)
	}
	if moved, err := a.AssignIP("switch", "10.0.0.1"); err != nil || moved != "router" {
		t.Fatalf("AssignIP move = (%q, %v), want router", moved, err)
	}
	if err := a.SaveDevice("switch", devices.Device{Name: "core-switch", Type: "switch", IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.SetLabels("10.0.0.1", []string{"managed", "poe"}); err != nil {
		t.Fatal(err)
	}
	if err := a.DismissHint("hostname:unifi"); err != nil {
		t.Fatal(err)
	}
	reg, err := a.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Devices) != 2 { // router (now empty) + core-switch
		t.Fatalf("Devices = %#v", reg.Devices)
	}
	if d := reg.DeviceForIP("10.0.0.1"); d == nil || d.Name != "core-switch" {
		t.Fatalf("DeviceForIP = %#v", d)
	}
	if got := reg.Labels["10.0.0.1"]; len(got) != 2 || got[0] != "managed" {
		t.Fatalf("Labels = %#v", got)
	}
	if !reg.Dismissed("hostname:unifi") {
		t.Fatal("dismissed hint lost")
	}
	if err := a.UnassignIP("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteDevice("router"); err != nil {
		t.Fatal(err)
	}
	reg, _ = a.ListDevices()
	if reg.DeviceForIP("10.0.0.1") != nil || len(reg.Devices) != 1 {
		t.Fatalf("after unassign/delete: %#v", reg.Devices)
	}
}

func TestLoadModelAppliesDeviceOverlay(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	if _, err := a.AssignIP("router", "10.0.0.10"); err != nil {
		t.Fatal(err)
	}
	if err := a.SetLabels("10.0.0.10", []string{"edge"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	writeSnapshot(t, path, graph.Snapshot{Nodes: []graph.Node{{
		IP: "10.0.0.10", Subnet: "10.0.0.0/24",
		Roles:  []graph.RoleAssertion{{Role: graph.RoleWebServer}},
		Scores: graph.ScoreSet{Composite: 1, Rank: 1},
	}}})
	m, err := a.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range m.Nodes {
		if n.ID == "10.0.0.10" {
			found = true
			if n.Device != "router" || len(n.Labels) != 1 || n.Labels[0] != "edge" {
				t.Fatalf("overlay missing: %#v", n)
			}
		}
	}
	if !found {
		t.Fatal("node not in model")
	}
}

func TestLoadModelSurvivesCorruptRegistry(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "devices.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	writeSnapshot(t, path, graph.Snapshot{Nodes: []graph.Node{{
		IP: "10.0.0.10", Subnet: "10.0.0.0/24",
	}}})
	a := &App{DataDir: dataDir, emitFn: func(string, ...interface{}) {}}
	if _, err := a.LoadModel(path); err != nil {
		t.Fatalf("corrupt registry must not block map load: %v", err)
	}
}
