package graph_test

import (
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/graph"
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
	}
	m := graph.Build(edges)
	m.InferRoles(graph.Evidence{})

	wants := map[string]graph.Role{
		"10.0.0.50": graph.RolePrinter,
		"10.0.0.55": graph.RolePrinter,
		"10.0.0.60": graph.RoleCamera,
		"10.0.0.70": graph.RoleMail,
	}
	for ip, role := range wants {
		if !hasRole(*m.Nodes[ip], role) {
			t.Errorf("%s: expected role %s, got %+v", ip, role, m.Nodes[ip].Roles)
		}
	}
	for _, ip := range []string{"10.0.0.80", "10.0.0.90"} {
		if got := m.Nodes[ip].TopRole(); got != graph.RoleUnknown {
			t.Errorf("%s: expected Unknown, got %s", ip, got)
		}
	}
}
