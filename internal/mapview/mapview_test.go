package mapview_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/reconcile"
	"github.com/BushidoCyb3r/defilade/internal/score"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
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

// largeFixture synthesizes a broad-scope snapshot in memory: 200 active /24
// subnets spread over 20 /16s, each with a web server, two mid-score unknown
// hosts, and a low-score client, plus cross-subnet edges to the top server.
// Ranks are assigned in creation order (composite descending), mirroring the
// real 14-day scan whose map blew past every readability target.
func largeFixture() graph.Snapshot {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var snap graph.Snapshot
	snap.Meta = graph.SnapshotMeta{Window: "336h", ClusterName: "test"}
	rank := 0
	addNode := func(ip, subnet string, role graph.Role, composite float64) {
		rank++
		n := graph.Node{
			IP: ip, Subnet: subnet, FirstSeen: t0, LastSeen: t0.Add(time.Hour),
			Scores: graph.ScoreSet{Composite: composite, Rank: rank},
		}
		if role != graph.RoleUnknown {
			n.Roles = []graph.RoleAssertion{{Role: role, Confidence: 0.9, Evidence: []string{"synthetic"}}}
		}
		snap.Nodes = append(snap.Nodes, n)
	}
	for i := 0; i < 200; i++ {
		subnet := fmt.Sprintf("10.%d.%d.0/24", i%20, i/20)
		base := fmt.Sprintf("10.%d.%d", i%20, i/20)
		addNode(base+".10", subnet, graph.RoleWebServer, 1.0/float64(rank+1))
	}
	for i := 0; i < 200; i++ {
		subnet := fmt.Sprintf("10.%d.%d.0/24", i%20, i/20)
		base := fmt.Sprintf("10.%d.%d", i%20, i/20)
		addNode(base+".20", subnet, graph.RoleUnknown, 0.5)
		addNode(base+".21", subnet, graph.RoleUnknown, 0.5)
		addNode(base+".30", subnet, graph.RoleUnknown, 0.05)
	}
	top := "10.0.0.10"
	for _, n := range snap.Nodes {
		if n.IP == top {
			continue
		}
		snap.Edges = append(snap.Edges, graph.Edge{
			Src: n.IP, Dst: top, Port: 443, ConnCount: 100,
			FirstSeen: t0, LastSeen: t0.Add(time.Hour),
		})
	}
	return snap
}

func hasOverviewFinding(findings []string) bool {
	for _, f := range findings {
		if strings.Contains(f, "overview") {
			return true
		}
	}
	return false
}

func TestBuildLargeSnapshotProducesBriefingOverview(t *testing.T) {
	mm := mapview.Build(largeFixture(), mapview.Options{})
	if got := mm.Elements(); got > config.MapTargetElements {
		t.Fatalf("overview has %d elements, target <= %d", got, config.MapTargetElements)
	}
	if !hasOverviewFinding(mm.Findings) {
		t.Fatal("overview does not explain that the map was condensed")
	}
}

func TestOverviewRetainsTopRanksAndAggregatesRest(t *testing.T) {
	snap := largeFixture()
	mm := mapview.Build(snap, mapview.Options{})
	if !mm.Overview {
		t.Fatal("large unfocused map must build in overview mode")
	}
	if got := len(mm.Groups); got > config.MapOverviewMaxGroups {
		t.Errorf("overview has %d groups, cap %d", got, config.MapOverviewMaxGroups)
	}
	rankByIP := map[string]int{}
	for _, n := range snap.Nodes {
		rankByIP[n.IP] = n.Scores.Rank
	}
	visible := map[string]bool{}
	aggregated := 0
	for _, n := range mm.Nodes {
		visible[n.ID] = true
		aggregated += n.AggCount
	}
	for _, n := range snap.Nodes {
		if n.Scores.Rank <= config.MapOverviewTopNodes && !visible[n.IP] {
			t.Errorf("rank-%d host %s missing from overview", n.Scores.Rank, n.IP)
		}
	}
	for id := range visible {
		if r, ok := rankByIP[id]; ok && r > config.MapOverviewTopNodes {
			t.Errorf("rank-%d host %s should be aggregated, not individually visible", r, id)
		}
	}
	if want := len(snap.Nodes) - config.MapOverviewTopNodes; aggregated != want {
		t.Errorf("aggregate counts sum to %d, want %d omitted hosts", aggregated, want)
	}
	// Small maps keep the detailed pipeline untouched.
	if small := mapview.Build(fixture(t), mapview.Options{}); small.Overview {
		t.Error("small map must not switch to overview mode")
	}
	// Focus keeps the detailed pipeline even on the large snapshot.
	if focused := mapview.Build(snap, mapview.Options{Focus: "10.0.0.0/24"}); focused.Overview {
		t.Error("focused map must not switch to overview mode")
	}
}

func TestOverviewGatewayBudget(t *testing.T) {
	snap := largeFixture()
	for i := 0; i < 40; i++ {
		snap.Meta.L2Gateways = append(snap.Meta.L2Gateways, graph.L2Gateway{
			MAC: fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i), Sensor: "s1", IPCount: int64(10 + i),
		})
	}
	mm := mapview.Build(snap, mapview.Options{})
	var gws []mapview.MapNode
	for _, n := range mm.Nodes {
		if n.Gateway {
			gws = append(gws, n)
		}
	}
	if len(gws) == 0 || len(gws) > config.MapOverviewMaxGroups {
		t.Fatalf("overview retained %d gateways, want 1..%d strongest", len(gws), config.MapOverviewMaxGroups)
	}
	// The strongest candidate (highest IPCount) must be among the retained.
	found := false
	for _, gw := range gws {
		if gw.ID == "gw:aa:bb:cc:dd:ee:27" { // i=39, IPCount 49
			found = true
		}
	}
	if !found {
		t.Error("strongest L2 gateway candidate was dropped")
	}
}

func TestOverviewDriftMarkedNodesRetained(t *testing.T) {
	snap := largeFixture()
	// 10.5.3.20 is a mid-score unknown ranked far below the top-node budget.
	d := snapshot.Diff{AppearedNodes: []graph.Node{{IP: "10.5.3.20", Subnet: "10.5.3.0/24"}}}
	mm := mapview.BuildDrift(snap, d, mapview.Options{})
	if !mm.Overview {
		t.Fatal("expected overview mode")
	}
	found := false
	for _, n := range mm.Nodes {
		if n.ID == "10.5.3.20" && n.Drift == "new" {
			found = true
		}
	}
	if !found {
		t.Error("drift-marked low-rank node must be individually retained in overview")
	}
}

func TestOverviewReconcileSkipsGhostsKeepsFindings(t *testing.T) {
	snap := largeFixture()
	assets := []reconcile.Asset{
		{IP: "10.0.0.10", Hostname: "web01", Role: "web server"},
		{IP: "10.0.200.99", Hostname: "old-nas", Role: "file server"}, // silent
	}
	res := reconcile.Compare(snap, assets)
	mm := mapview.BuildReconcile(snap, res, assets, mapview.Options{})
	if !mm.Overview {
		t.Fatal("expected overview mode")
	}
	for _, n := range mm.Nodes {
		if strings.HasPrefix(n.ID, "asset:") {
			t.Errorf("overview must not ghost individual silent assets, found %s", n.ID)
		}
	}
	silentFinding, markedFinding := false, false
	for _, f := range mm.Findings {
		if strings.Contains(f, "documented assets produced no observed traffic") {
			silentFinding = true
		}
		if strings.Contains(f, "flagged") {
			markedFinding = true
		}
	}
	if !silentFinding {
		t.Errorf("silent-asset finding missing: %v", mm.Findings)
	}
	// Nearly every observed host is undocumented — far more marked nodes
	// than the top-node budget. The overview must say some were omitted.
	if !markedFinding {
		t.Errorf("expected a finding about flagged nodes omitted from the overview: %v", mm.Findings)
	}
	if got := len(mm.Nodes); got > config.MapOverviewTopNodes+2*config.MapOverviewMaxGroups {
		t.Errorf("overview node count %d exceeds retained+aggregates+gateways bound", got)
	}
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

func TestBuildDriftAnnotatesNodesAndCriticalEdges(t *testing.T) {
	from := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.1", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 1}},
			{IP: "10.0.0.2", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 2}},
			{IP: "10.0.0.3", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 3}},
		},
		Edges: []graph.Edge{{Src: "10.0.0.3", Dst: "10.0.0.1", Port: 53, ConnCount: 1}},
	}
	to := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.1", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 7}},
			{IP: "10.0.0.2", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 1}},
			{IP: "10.0.0.4", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 2}},
		},
		Edges: []graph.Edge{{Src: "10.0.0.4", Dst: "10.0.0.2", Port: 445, ConnCount: 1}},
	}
	d := snapshot.Compare(from, to, snapshot.DiffOptions{RankDelta: 5, TopN: 2})
	m := mapview.BuildDrift(to, d, mapview.Options{})
	wantNodes := map[string]string{"10.0.0.1": "rank-down", "10.0.0.3": "vanished", "10.0.0.4": "new"}
	for _, n := range m.Nodes {
		if want, ok := wantNodes[n.ID]; ok {
			if n.Drift != want {
				t.Errorf("node %s drift = %q, want %q", n.ID, n.Drift, want)
			}
			delete(wantNodes, n.ID)
		}
	}
	if len(wantNodes) != 0 {
		t.Fatalf("drift nodes missing from map: %v", wantNodes)
	}
	wantEdges := map[string]bool{"new": false, "vanished": false}
	for _, e := range m.Edges {
		if _, ok := wantEdges[e.Drift]; ok {
			wantEdges[e.Drift] = true
		}
	}
	for state, found := range wantEdges {
		if !found {
			t.Errorf("missing %s drift edge", state)
		}
	}
}

func TestBuildReconcileFlagsGhostsAndLabels(t *testing.T) {
	snap := fixture(t)
	assets := []reconcile.Asset{
		{IP: "10.0.1.10", Hostname: "dc01", Role: "Domain Controller", Segment: "Server VLAN"},
		{IP: "10.0.1.11", Role: "file server"},                      // contradicted (observed DNS)
		{IP: "10.0.1.99", Hostname: "old-nas", Role: "file server"}, // silent, group exists -> ghost
		{IP: "10.0.99.7", Role: "database"},                         // silent, in blind-spot group -> ghost in hatched box
		{IP: "10.0.50.7", Role: "database"},                         // silent, no group at all -> findings only
	}
	res := reconcile.Compare(snap, assets)
	mm := mapview.BuildReconcile(snap, res, assets, mapview.Options{})

	byID := map[string]mapview.MapNode{}
	for _, n := range mm.Nodes {
		byID[n.ID] = n
	}
	if byID["10.0.1.11"].Drift != "contradicted" {
		t.Errorf("dns node drift = %q, want contradicted", byID["10.0.1.11"].Drift)
	}
	ghost, ok := byID["asset:10.0.1.99"]
	if !ok || ghost.Drift != "silent" || ghost.Group != "g:10.0.1.0/24" {
		t.Errorf("ghost node = %+v", ghost)
	}
	if blindGhost, ok := byID["asset:10.0.99.7"]; !ok || blindGhost.Group != "g:10.0.99.0/24" {
		t.Errorf("blind-spot ghost = %+v, want it inside the hatched group", blindGhost)
	}
	if _, ok := byID["asset:10.0.50.7"]; ok {
		t.Error("silent asset without any group must not be ghosted")
	}
	// every undocumented workstation must be flagged, not aggregated
	if byID["10.0.2.30"].Drift != "undocumented" {
		t.Errorf("workstation drift = %q, want undocumented", byID["10.0.2.30"].Drift)
	}
	var serverGroup mapview.Group
	for _, g := range mm.Groups {
		if g.CIDR == "10.0.1.0/24" {
			serverGroup = g
		}
	}
	if serverGroup.Label != "10.0.1.0/24 — Server VLAN" {
		t.Errorf("group label = %q, want segment enrichment", serverGroup.Label)
	}
	if len(mm.Findings) < 3 {
		t.Errorf("findings = %v, want silent/undocumented/contradicted counts", mm.Findings)
	}
}
