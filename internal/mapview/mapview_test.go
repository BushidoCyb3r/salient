package mapview_test

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/score"
)

// fixture builds a real scored snapshot: DC/DNS/file server in 10.0.1.0/24,
// 12 workstations in 10.0.2.0/24, one lone host in 10.0.9.0/24 (sparse), and
// a zero-coverage in-scope CIDR for the blind-spot finding.
func fixture(t *testing.T) graph.Snapshot {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	dc, dns, file := "10.0.1.10", "10.0.1.11", "10.0.1.20"
	var edges []graph.Edge
	add := func(src, dst string, port uint16, conns int64) {
		edges = append(edges, graph.Edge{
			Src: src, Dst: dst, Port: port, ConnCount: conns,
			FirstSeen: t0, LastSeen: t0.Add(24 * time.Hour),
		})
	}
	wsIPs := []string{
		"10.0.2.30", "10.0.2.31", "10.0.2.32", "10.0.2.33", "10.0.2.34", "10.0.2.35",
		"10.0.2.36", "10.0.2.37", "10.0.2.38", "10.0.2.39", "10.0.2.40", "10.0.2.41",
	}
	for _, ws := range wsIPs {
		add(ws, dc, 88, 500)
		add(ws, dns, 53, 900)
		add(ws, file, 445, 60)
	}
	add("10.0.9.5", dc, 88, 20) // one host in its own /24: sparse
	// cross-subnet traffic exists (workstations -> 10.0.1.0/24 servers), so
	// the no-L2 fallback should synthesize inferred gateways on both groups.

	m := graph.Build(edges)
	m.InferRoles(graph.Evidence{
		Kerberos: map[string]graph.RoleEvidence{dc: {Clients: 13}},
		LDAP:     map[string]graph.RoleEvidence{dc: {Clients: 13}},
		DNS:      map[string]graph.RoleEvidence{dns: {Clients: 12}},
		SMB:      map[string]graph.RoleEvidence{file: {Clients: 12}},
	})
	score.Score(m)
	return m.Snapshot(graph.SnapshotMeta{
		Window: "24h", ClusterName: "test", ZeroCovCIDRs: []string{"10.0.99.0/24"},
	})
}

func TestBuildGroupsAndSparseCollapse(t *testing.T) {
	mm := mapview.Build(fixture(t), mapview.Options{})
	var main, sparse *mapview.Group
	for i := range mm.Groups {
		g := &mm.Groups[i]
		switch g.CIDR {
		case "10.0.1.0/24":
			main = g
		case "":
			if g.Sparse {
				sparse = g
			}
		}
	}
	if main == nil {
		t.Fatal("expected group for 10.0.1.0/24")
	}
	if sparse == nil {
		t.Fatal("expected sparse group collapsing the lone 10.0.9.0/24 host")
	}
	// The lone host must not have its own visible group box.
	for _, g := range mm.Groups {
		if g.CIDR == "10.0.9.0/24" {
			t.Errorf("10.0.9.0/24 should have collapsed into sparse, found its own group: %+v", g)
		}
	}
}

func TestBuildClientAggregation(t *testing.T) {
	mm := mapview.Build(fixture(t), mapview.Options{})
	var agg *mapview.MapNode
	for i := range mm.Nodes {
		if mm.Nodes[i].AggCount > 0 && (agg == nil || mm.Nodes[i].AggCount > agg.AggCount) {
			agg = &mm.Nodes[i]
		}
	}
	if agg == nil {
		t.Fatal("expected an aggregated workstation meta-node")
	}
	if agg.AggCount < 10 {
		t.Errorf("expected most of the 12 workstations aggregated, got AggCount=%d", agg.AggCount)
	}
	// Server roles must stay individually visible, never aggregated.
	roles := map[string]bool{}
	for _, n := range mm.Nodes {
		roles[n.Role] = true
	}
	for _, want := range []string{"DomainController", "DNSServer", "FileServer"} {
		if !roles[want] {
			t.Errorf("expected visible node with role %s, got roles %v", want, roles)
		}
	}
}

func TestBuildInferredGatewayFallback(t *testing.T) {
	mm := mapview.Build(fixture(t), mapview.Options{})
	var gw *mapview.MapNode
	for i := range mm.Nodes {
		if mm.Nodes[i].Gateway {
			gw = &mm.Nodes[i]
		}
	}
	if gw == nil {
		t.Fatal("expected an inferred gateway (no L2 evidence in fixture)")
	}
	if !gw.Inferred {
		t.Error("gateway synthesized without L2 evidence must be marked Inferred")
	}
}

func TestBuildObservedGatewayFromL2Evidence(t *testing.T) {
	snap := fixture(t)
	snap.Meta.L2Gateways = []graph.L2Gateway{{MAC: "aa:bb:cc:dd:ee:ff", Sensor: "s1", IPCount: 40}}
	mm := mapview.Build(snap, mapview.Options{})
	var gw *mapview.MapNode
	for i := range mm.Nodes {
		if mm.Nodes[i].Gateway {
			gw = &mm.Nodes[i]
		}
	}
	if gw == nil {
		t.Fatal("expected an observed gateway node from L2 evidence")
	}
	if gw.Inferred {
		t.Error("gateway backed by L2 evidence must not be marked Inferred")
	}
}

func TestBuildBlindSpotFinding(t *testing.T) {
	mm := mapview.Build(fixture(t), mapview.Options{})
	found := false
	for _, g := range mm.Groups {
		if g.CIDR == "10.0.99.0/24" && g.BlindSpot {
			found = true
		}
	}
	if !found {
		t.Error("expected a blind-spot group for the zero-coverage CIDR")
	}
	if len(mm.Findings) == 0 {
		t.Error("expected at least one finding string for the blind spot")
	}
}

func TestBuildNoiseFloorDropsLowVolumeEdges(t *testing.T) {
	// min-conns above every bundled edge's total should leave zero edges.
	mm := mapview.Build(fixture(t), mapview.Options{MinConns: 1_000_000})
	if len(mm.Edges) != 0 {
		t.Errorf("expected all edges dropped by noise floor, got %d", len(mm.Edges))
	}
}

func TestBuildFocusRestrictsToOneSubnet(t *testing.T) {
	mm := mapview.Build(fixture(t), mapview.Options{Focus: "10.0.1.0/24"})
	for _, g := range mm.Groups {
		if g.CIDR != "" && g.CIDR != "10.0.1.0/24" {
			t.Errorf("--focus should exclude other groups, found %s", g.CIDR)
		}
	}
}

func TestElementsCountAndDeterminism(t *testing.T) {
	snap := fixture(t)
	a := mapview.Build(snap, mapview.Options{})
	b := mapview.Build(snap, mapview.Options{})
	if a.Elements() != b.Elements() {
		t.Fatalf("Build is not deterministic in element count: %d vs %d", a.Elements(), b.Elements())
	}
	for i := range a.Nodes {
		if a.Nodes[i].ID != b.Nodes[i].ID {
			t.Fatalf("Build node ordering is not deterministic at index %d: %s vs %s", i, a.Nodes[i].ID, b.Nodes[i].ID)
		}
	}
}
