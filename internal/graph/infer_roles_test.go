package graph_test

import (
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// Device-service roles: printer/camera fire at one client, mail needs two.
func TestInferDeviceServiceRoles(t *testing.T) {
	edges := []graph.Edge{
		{Src: "10.0.0.2", Dst: "10.0.0.50", Port: 631, ConnCount: 3},   // printer via ipp
		{Src: "10.0.0.2", Dst: "10.0.0.55", Port: 9100, ConnCount: 2},  // printer via jetdirect
		{Src: "10.0.0.2", Dst: "10.0.0.60", Port: 554, ConnCount: 10},  // camera via rtsp
		{Src: "10.0.0.2", Dst: "10.0.0.70", Port: 25, ConnCount: 5},    // mail client 1
		{Src: "10.0.0.3", Dst: "10.0.0.70", Port: 993, ConnCount: 5},   // mail client 2
		{Src: "10.0.0.2", Dst: "10.0.0.80", Port: 587, ConnCount: 5},   // only 1 client — no mail role
		{Src: "10.0.0.2", Dst: "10.0.0.90", Port: 49200, ConnCount: 5}, // unknown port — nothing
		{Src: "10.0.0.9", Dst: "10.0.0.40", Port: 5246, ConnCount: 8},  // capwap → NetworkGear (WLC)
		{Src: "10.0.0.2", Dst: "10.0.0.41", Port: 161, ConnCount: 8},   // snmp only — not gear
	}
	m := graph.Build(edges)
	m.InferRoles(graph.Evidence{})

	wants := map[string]graph.Role{
		"10.0.0.50": graph.RolePrinter,
		"10.0.0.55": graph.RolePrinter,
		"10.0.0.60": graph.RoleCamera,
		"10.0.0.70": graph.RoleMail,
		"10.0.0.40": graph.RoleNetworkGear,
	}
	for ip, role := range wants {
		if !hasRole(*m.Nodes[ip], role) {
			t.Errorf("%s: expected role %s, got %+v", ip, role, m.Nodes[ip].Roles)
		}
	}
	for _, ip := range []string{"10.0.0.80", "10.0.0.90", "10.0.0.41"} {
		if got := m.Nodes[ip].TopRole(); got != graph.RoleUnknown {
			t.Errorf("%s: expected Unknown, got %s", ip, got)
		}
	}
}

// DHCPServer fires on real lease evidence (server.address on an ACK/OFFER
// record) — a distinct signal from any conn-log edge (broadcast-heavy
// protocol, dhcp.log is a separate Zeek dataset from conn.log). Nodes are
// still keyed off conn edges (dhcp.log evidence alone doesn't create a
// node), so both hosts also need a port-67 edge, same as every other
// evidence-driven role's test in this package.
func TestInferDHCPServerRole(t *testing.T) {
	edges := []graph.Edge{
		{Src: "10.0.0.100", Dst: "10.0.0.1", Port: 67, ConnCount: 5},
		{Src: "10.0.0.101", Dst: "10.0.0.2", Port: 67, ConnCount: 5},
	}
	m := graph.Build(edges)
	m.InferRoles(graph.Evidence{
		DHCP: map[string]graph.RoleEvidence{
			"10.0.0.1": {Clients: 5}, // real server, above RoleDHCPMinClients=2
			"10.0.0.2": {Clients: 1}, // below threshold — no role
		},
	})
	if got := m.Nodes["10.0.0.1"].TopRole(); got != graph.RoleDHCPServer {
		t.Errorf("10.0.0.1: expected DHCPServer, got %s", got)
	}
	if got := m.Nodes["10.0.0.2"].TopRole(); got != graph.RoleUnknown {
		t.Errorf("10.0.0.2: expected Unknown (below threshold), got %s", got)
	}
}
