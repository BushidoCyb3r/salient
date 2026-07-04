package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/devices"
	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
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

func TestRoleOverrideOverlayAndTierRemap(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	for ip, role := range map[string]string{
		"10.0.0.10": "Printer",    // known role -> client tier
		"10.0.0.11": "MailServer", // known role -> service tier
		"10.0.0.12": "Octoprint",  // custom text -> tier unchanged
	} {
		if err := a.SetRole(ip, role); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	mkNode := func(ip string) graph.Node {
		return graph.Node{IP: ip, Subnet: "10.0.0.0/24",
			Roles:  []graph.RoleAssertion{{Role: graph.RoleWebServer, Confidence: 0.7}},
			Scores: graph.ScoreSet{Composite: 1, Rank: 1}}
	}
	writeSnapshot(t, path, graph.Snapshot{Nodes: []graph.Node{
		mkNode("10.0.0.10"), mkNode("10.0.0.11"), mkNode("10.0.0.12"),
	}})
	m, err := a.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]mapview.MapNode{}
	for _, n := range m.Nodes {
		got[n.ID] = n
	}
	if n := got["10.0.0.10"]; n.RoleOverride != "Printer" || n.Tier != mapview.TierClient {
		t.Errorf("10.0.0.10 = override %q tier %q, want Printer/client", n.RoleOverride, n.Tier)
	}
	if n := got["10.0.0.11"]; n.RoleOverride != "MailServer" || n.Tier != mapview.TierService {
		t.Errorf("10.0.0.11 = override %q tier %q, want MailServer/service", n.RoleOverride, n.Tier)
	}
	// WebServer inference puts the node in the service tier; custom text must not move it.
	if n := got["10.0.0.12"]; n.RoleOverride != "Octoprint" || n.Tier != mapview.TierService {
		t.Errorf("10.0.0.12 = override %q tier %q, want Octoprint/service(unchanged)", n.RoleOverride, n.Tier)
	}
	// Inferred role is preserved alongside the override.
	if got["10.0.0.10"].Role != string(graph.RoleWebServer) {
		t.Errorf("inferred role destroyed: %q", got["10.0.0.10"].Role)
	}
	// Clearing removes the override.
	if err := a.SetRole("10.0.0.10", ""); err != nil {
		t.Fatal(err)
	}
	reg, _ := a.ListDevices()
	if _, ok := reg.RoleOverrides["10.0.0.10"]; ok {
		t.Fatal("override not cleared")
	}
}

func TestHostnameHints(t *testing.T) {
	nodes := []graph.Node{
		{IP: "192.168.20.1", Hostnames: []string{"udm"}},
		{IP: "10.10.40.1", Hostnames: []string{"udm"}},
		{IP: "10.18.61.1", Hostnames: []string{"udm"}},
		{IP: "10.0.0.5", Hostnames: []string{"nas"}}, // single IP — no hint
		{IP: "10.0.0.6"},                             // no hostname
		{IP: "10.0.0.7", Hostnames: []string{"printer"}},
		{IP: "10.0.0.8", Hostnames: []string{"printer"}},
	}
	var reg devices.Registry
	hints := hostnameHints(nodes, &reg)
	if len(hints) != 2 {
		t.Fatalf("hints = %#v", hints)
	}
	if hints[0].Key != "hostname:printer" || len(hints[0].IPs) != 2 {
		t.Fatalf("hint[0] = %#v", hints[0])
	}
	if hints[1].Key != "hostname:udm" || len(hints[1].IPs) != 3 || hints[1].Hostname != "udm" {
		t.Fatalf("hint[1] = %#v", hints[1])
	}

	// Dismissed hints stay dismissed.
	reg.Dismiss("hostname:printer")
	if got := hostnameHints(nodes, &reg); len(got) != 1 || got[0].Key != "hostname:udm" {
		t.Fatalf("after dismiss: %#v", got)
	}

	// A hint whose IPs are already all in one device disappears.
	reg.Assign("router", "192.168.20.1")
	reg.Assign("router", "10.10.40.1")
	reg.Assign("router", "10.18.61.1")
	if got := hostnameHints(nodes, &reg); len(got) != 0 {
		t.Fatalf("linked hint should vanish: %#v", got)
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
