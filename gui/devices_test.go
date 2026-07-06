package main

import (
	"fmt"
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

func TestLoadModelCollapsesSameDeviceRole(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	ips := []string{"192.168.20.1", "10.10.40.1", "10.18.61.1"}
	roles := []graph.Role{graph.RoleNetworkGear, graph.RoleDNS, graph.RoleWebServer}
	for _, ip := range ips {
		if _, err := a.AssignIP("UDM Pro", ip); err != nil {
			t.Fatal(err)
		}
	}

	var nodes []graph.Node
	for i, ip := range ips {
		nodes = append(nodes, graph.Node{
			IP: ip, Subnet: graph.Subnet(ip),
			Roles:  []graph.RoleAssertion{{Role: roles[i], Confidence: 0.7}},
			Scores: graph.ScoreSet{Composite: 1 - float64(i)*0.1, Rank: i + 1},
		})
	}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	writeSnapshot(t, path, graph.Snapshot{Nodes: nodes})

	m, err := a.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	var devNodes []mapview.MapNode
	for _, n := range m.Nodes {
		if n.Device == "UDM Pro" {
			devNodes = append(devNodes, n)
		}
		for _, ip := range ips {
			if n.ID == ip {
				t.Fatalf("%s still rendered as its own node", ip)
			}
		}
	}
	if len(devNodes) != 1 {
		t.Fatalf("UDM Pro visible nodes = %d, want 1: %#v", len(devNodes), devNodes)
	}
	agg := devNodes[0]
	if agg.AggCount != len(ips) {
		t.Fatalf("aggregate = %#v, want %d members", agg, len(ips))
	}
	if agg.Group == "" || agg.Group == "g:"+graph.Subnet(ips[0]) {
		t.Fatalf("aggregate group = %q, want standalone device group", agg.Group)
	}
	var groupLabel string
	for _, g := range m.Groups {
		if g.ID == agg.Group {
			groupLabel = g.Label
		}
	}
	if groupLabel != "UDM Pro" {
		t.Fatalf("device group label = %q, want UDM Pro", groupLabel)
	}

	hosts, err := a.AggregateHosts(path, agg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != len(ips) {
		t.Fatalf("AggregateHosts(%q) = %d hosts, want %d: %#v", agg.ID, len(hosts), len(ips), hosts)
	}
	got := map[string]bool{}
	for _, h := range hosts {
		if h.Device != "UDM Pro" {
			t.Fatalf("host overlay missing: %#v", h)
		}
		got[h.ID] = true
	}
	for _, ip := range ips {
		if !got[ip] {
			t.Fatalf("missing aggregate member %s in %#v", ip, hosts)
		}
	}
}

func TestLoadModelCollapsesCustomRoleLabel(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	for _, ip := range []string{"10.0.1.10", "10.0.2.10"} {
		if err := a.SetRole(ip, "UDM Pro"); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{"10.0.3.10", "10.0.4.10"} {
		if err := a.SetRole(ip, "Printer"); err != nil {
			t.Fatal(err)
		}
	}
	nodes := []graph.Node{
		{IP: "10.0.1.10", Subnet: "10.0.1.0/24", Scores: graph.ScoreSet{Composite: 1, Rank: 1}},
		{IP: "10.0.2.10", Subnet: "10.0.2.0/24", Scores: graph.ScoreSet{Composite: 0.9, Rank: 2}},
		{IP: "10.0.3.10", Subnet: "10.0.3.0/24", Scores: graph.ScoreSet{Composite: 0.8, Rank: 3}},
		{IP: "10.0.4.10", Subnet: "10.0.4.0/24", Scores: graph.ScoreSet{Composite: 0.7, Rank: 4}},
	}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	writeSnapshot(t, path, graph.Snapshot{Nodes: nodes})

	m, err := a.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	var udm *mapview.MapNode
	for i := range m.Nodes {
		n := &m.Nodes[i]
		if n.Device == "UDM Pro" {
			udm = n
		}
	}
	if udm == nil || udm.AggCount != 2 {
		t.Fatalf("UDM Pro custom-role aggregate = %#v, want 2-member aggregate", udm)
	}
	for _, ip := range []string{"10.0.3.10", "10.0.4.10"} {
		if !nodeInModel(m, ip) {
			t.Fatalf("generic Printer role %s should not collapse", ip)
		}
	}
}

func TestHostnameHints(t *testing.T) {
	nodes := []graph.Node{
		{IP: "192.168.20.1", Hostnames: []string{"udm"}},
		{IP: "10.10.40.1", Hostnames: []string{"udm"}},
		{IP: "10.18.61.1", Hostnames: []string{"udm"}},
		{IP: "10.0.0.5", Hostnames: []string{"nas"}}, // single IP — no hint
		{IP: "10.0.0.6"}, // no hostname
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

func TestMACHints(t *testing.T) {
	nodes := []graph.Node{
		{IP: "10.0.0.1", MAC: "24:5a:4c:11:22:33"},
		{IP: "10.0.0.2", MAC: "24:5a:4c:11:22:33"}, // same NIC, two VLAN IPs
		{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff"}, // single IP — no hint
		{IP: "10.0.0.6"}, // no MAC
	}
	var reg devices.Registry
	hints := macHints(nodes, &reg)
	if len(hints) != 1 {
		t.Fatalf("hints = %#v", hints)
	}
	if hints[0].Key != "mac:24:5a:4c:11:22:33" || len(hints[0].IPs) != 2 {
		t.Fatalf("hint = %#v", hints[0])
	}
	// Vendor rides the Hostname field for display.
	if hints[0].Hostname != "Ubiquiti" {
		t.Errorf("expected vendor Ubiquiti in hint, got %q", hints[0].Hostname)
	}
	// Dismissed MAC hints stay dismissed.
	reg.Dismiss("mac:24:5a:4c:11:22:33")
	if got := macHints(nodes, &reg); len(got) != 0 {
		t.Errorf("dismissed MAC hint reappeared: %#v", got)
	}
}

func TestPinToMapOverlaysAndRetains(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	// >120 elements forces briefing-overview mode, where retention (and thus
	// pinning) matters; a smaller map shows every node in detail regardless.
	var nodes []graph.Node
	for i := 0; i < 130; i++ {
		nodes = append(nodes, graph.Node{
			IP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Subnet: "10.0.0.0/24",
			Scores: graph.ScoreSet{Composite: 1.0 - float64(i)*0.005, Rank: i + 1},
		})
	}
	writeSnapshot(t, path, graph.Snapshot{Nodes: nodes})

	pin := "10.0.0.55" // below the top-N cut — normally aggregated
	if err := a.PinToMap(pin); err != nil {
		t.Fatal(err)
	}
	m, err := a.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range m.Nodes {
		if n.ID == pin {
			found = true
			if !n.Pinned {
				t.Error("pinned node not flagged Pinned in overlay")
			}
		}
	}
	if !found {
		t.Fatalf("pinned host %s not retained as its own node", pin)
	}

	// Unpin returns it to the aggregate.
	if err := a.UnpinFromMap(pin); err != nil {
		t.Fatal(err)
	}
	m, _ = a.LoadModel(path)
	for _, n := range m.Nodes {
		if n.ID == pin {
			t.Fatalf("unpinned host still its own node")
		}
	}
}

func TestShowAllPrivatePromotesRFC1918(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	var nodes []graph.Node
	rank := 0
	add := func(ip, subnet string) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: 1.0 - float64(rank)*0.002, Rank: rank}})
	}
	// 50 private hosts (past the top-N cut) + enough external to force overview.
	for i := 0; i < 50; i++ {
		add(fmt.Sprintf("10.0.0.%d", i+1), "10.0.0.0/24")
	}
	for i := 0; i < 100; i++ {
		add(fmt.Sprintf("8.8.%d.1", i), fmt.Sprintf("8.8.%d.0/24", i))
	}
	writeSnapshot(t, path, graph.Snapshot{Nodes: nodes})

	// Off: a low-ranked private host is aggregated.
	m, err := a.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if nodeInModel(m, "10.0.0.50") {
		t.Fatal("host 10.0.0.50 should be aggregated by default")
	}

	// On: every private host is its own node.
	if err := a.SetShowAllPrivate(true); err != nil {
		t.Fatal(err)
	}
	m, _ = a.LoadModel(path)
	for i := 0; i < 50; i++ {
		if !nodeInModel(m, fmt.Sprintf("10.0.0.%d", i+1)) {
			t.Fatalf("private host 10.0.0.%d not promoted", i+1)
		}
	}
}

func nodeInModel(m *mapview.Model, id string) bool {
	for _, n := range m.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
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
