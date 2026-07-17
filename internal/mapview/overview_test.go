package mapview

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
)

// TestOverviewKeepsTruePrefixGroups guards the reported bug: coarsening
// blended real VLANs (10.18.61.0/26 hosts) into a phantom "10.18.0.0/16"
// box. Groups must keep their true grouping prefix; when the cap overflows,
// the least important groups merge into "other internal networks" instead.
func TestOverviewKeepsTruePrefixGroups(t *testing.T) {
	var nodes []graph.Node
	rank := 0
	add := func(ip, subnet string) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: 0.5, Rank: rank}})
	}
	// Operator VLANs, ranked highest — must keep their true /24 boxes.
	for i := 0; i < 10; i++ {
		add(fmt.Sprintf("10.18.61.%d", i+1), "10.18.61.0/24")
		add(fmt.Sprintf("10.10.40.%d", i+1), "10.10.40.0/24")
	}
	// Noise: 30 more /24s so the group count blows well past the cap.
	for i := 0; i < 30; i++ {
		add(fmt.Sprintf("10.20.%d.1", i), fmt.Sprintf("10.20.%d.0/24", i))
		add(fmt.Sprintf("10.20.%d.2", i), fmt.Sprintf("10.20.%d.0/24", i))
	}
	m := buildOverview(graph.Snapshot{Nodes: nodes}, Options{GroupPrefix: 24}, nil, nil, 0)

	cidrs := map[string]bool{}
	other := false
	for _, g := range m.Groups {
		cidrs[g.CIDR] = true
		if g.ID == "g:other" {
			other = true
		}
		if g.CIDR == "" {
			continue
		}
		p, err := netip.ParsePrefix(g.CIDR)
		if err != nil {
			t.Fatalf("group CIDR %q does not parse: %v", g.CIDR, err)
		}
		if p.Bits() < 24 {
			t.Errorf("group %q coarser than /24 — phantom supernet", g.CIDR)
		}
	}
	if !cidrs["10.18.61.0/24"] || !cidrs["10.10.40.0/24"] {
		t.Errorf("top VLANs lost their true boxes, groups: %v", cidrs)
	}
	// Segment-flow: 32 VLANs is well under MapSegmentMaxGroups, so every real
	// segment keeps its own box and there is no "other internal networks" lump.
	if len(m.Groups) > config.MapSegmentMaxGroups {
		t.Errorf("%d groups, cap %d", len(m.Groups), config.MapSegmentMaxGroups)
	}
	if other {
		t.Error("no VLAN should overflow to 'other internal networks' below the segment cap")
	}
	if !cidrs["10.20.5.0/24"] {
		t.Errorf("a low-traffic VLAN lost its box, groups: %v", cidrs)
	}
}

// TestOverviewPinsLowRankHost: a pinned host far below the top-N cut still
// gets its own map node instead of collapsing into the aggregate.
func TestOverviewPinsLowRankHost(t *testing.T) {
	var nodes []graph.Node
	for i := 0; i < 60; i++ {
		nodes = append(nodes, graph.Node{
			IP: fmt.Sprintf("10.0.0.%d", i+1), Subnet: "10.0.0.0/24",
			Scores: graph.ScoreSet{Composite: 1.0 - float64(i)*0.01, Rank: i + 1},
		})
	}
	pin := "10.0.0.55" // rank 55 — far outside any per-segment top-N
	opts := Options{GroupPrefix: 24, Pinned: map[string]bool{pin: true}}
	m := buildOverview(graph.Snapshot{Nodes: nodes}, opts, nil, nil, 0)

	var found bool
	for _, n := range m.Nodes {
		if n.ID == pin {
			found = true
		}
	}
	if !found {
		t.Fatalf("pinned host %s not retained as its own node", pin)
	}
	// It must not also appear inside an aggregate's members.
	for _, members := range m.AggMembers {
		for _, mem := range members {
			if mem.ID == pin {
				t.Errorf("pinned host also collapsed into aggregate %q", mem.ID)
			}
		}
	}
}

func TestOverviewRetainsDeclaredUniFiDevice(t *testing.T) {
	var nodes []graph.Node
	for i := 0; i < 60; i++ {
		nodes = append(nodes, graph.Node{
			IP: fmt.Sprintf("10.0.0.%d", i+1), Subnet: "10.0.0.0/24",
			Scores: graph.ScoreSet{Composite: 1.0 - float64(i)*0.01, Rank: i + 1},
		})
	}
	ip := "10.0.0.55"
	m := buildOverview(graph.Snapshot{Nodes: nodes}, Options{
		GroupPrefix: 24,
		DeclaredDevices: map[string]DeclaredDevice{
			ip: {Name: "Core Switch", Model: "USW-Pro-24"},
		},
	}, nil, nil, 0)
	for _, n := range m.Nodes {
		if n.ID != ip {
			continue
		}
		if n.Device != "Core Switch" || n.DeviceType != "USW-Pro-24" || n.Role != string(graph.RoleNetworkGear) || n.Tier != TierCore {
			t.Fatalf("declared device overlay = %+v", n)
		}
		if !hasEvidence(n.Evidence, "device identity imported from UniFi Network: Core Switch (USW-Pro-24)") {
			t.Fatalf("declared device evidence = %v", n.Evidence)
		}
		return
	}
	t.Fatal("declared UniFi device was aggregated out of the overview")
}

// TestOverviewRetainAllPrivate promotes every RFC1918 host to its own node
// while external peers still collapse, and enforces the cap.
func TestOverviewRetainAllPrivate(t *testing.T) {
	var nodes []graph.Node
	rank := 0
	add := func(ip, subnet string) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: 1.0 - float64(rank)*0.001, Rank: rank}})
	}
	// 40 private hosts across two VLANs (well past the top-N cut).
	for i := 0; i < 20; i++ {
		add(fmt.Sprintf("10.10.40.%d", i+1), "10.10.40.0/24")
		add(fmt.Sprintf("192.168.5.%d", i+1), "192.168.5.0/24")
	}
	// External peers — must NOT be promoted.
	for i := 0; i < 30; i++ {
		add(fmt.Sprintf("8.8.%d.1", i), fmt.Sprintf("8.8.%d.0/24", i))
	}
	// A connection between two low-ranked private hosts + lots of filler edges
	// so a normal element budget would trim it. Show-all-private must keep it.
	var edges []graph.Edge
	edges = append(edges, graph.Edge{Src: "10.10.40.20", Dst: "192.168.5.20", Port: 445, ConnCount: 1})
	for i := 0; i < 40; i++ {
		edges = append(edges, graph.Edge{Src: fmt.Sprintf("10.10.40.%d", i%20+1), Dst: fmt.Sprintf("192.168.5.%d", i%20+1), Port: 80, ConnCount: int64(1000 - i)})
	}
	m := buildOverview(graph.Snapshot{Nodes: nodes, Edges: edges},
		Options{GroupPrefix: 24, RetainAllPrivate: true, MinConns: 1}, nil, nil, 999)

	var haveLowEdge bool
	for _, e := range m.Edges {
		if (e.Src == "10.10.40.20" && e.Dst == "192.168.5.20") || (e.Src == "192.168.5.20" && e.Dst == "10.10.40.20") {
			haveLowEdge = true
		}
	}
	if !haveLowEdge {
		t.Errorf("connection between visible private hosts was trimmed under show-all-private")
	}

	own := map[string]bool{}
	for _, n := range m.Nodes {
		own[n.ID] = true
	}
	for i := 0; i < 20; i++ {
		if !own[fmt.Sprintf("10.10.40.%d", i+1)] || !own[fmt.Sprintf("192.168.5.%d", i+1)] {
			t.Fatalf("private host not promoted: 10.10.40.%d / 192.168.5.%d", i+1, i+1)
		}
	}
	// No external host got its own node.
	for id := range own {
		if strings.HasPrefix(id, "8.8.") {
			t.Errorf("external host %s promoted — should stay in the external aggregate", id)
		}
	}
}

// TestOverviewRetainAllPrivateKeepsEveryVLANBox: a lightly-populated real VLAN
// must keep its own group box under show-all-private, never lumped into the
// "other internal networks" overflow bucket.
func TestOverviewRetainAllPrivateKeepsEveryVLANBox(t *testing.T) {
	var nodes []graph.Node
	rank := 0
	add := func(ip, subnet string) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: 1.0 - float64(rank)*0.001, Rank: rank}})
	}
	// 20 busy /24 VLANs (enough to overflow the group cap) …
	for v := 0; v < 20; v++ {
		for h := 0; h < 4; h++ {
			add(fmt.Sprintf("10.10.%d.%d", v, h+1), fmt.Sprintf("10.10.%d.0/24", v))
		}
	}
	// … plus one sparse, real VLAN the cap would otherwise overflow.
	add("10.10.60.1", "10.10.60.0/24")
	add("10.10.60.2", "10.10.60.0/24")

	m := buildOverview(graph.Snapshot{Nodes: nodes},
		Options{GroupPrefix: 24, RetainAllPrivate: true}, nil, nil, 999)

	haveVLAN, haveOverflow := false, false
	nodeShown := map[string]bool{}
	for _, g := range m.Groups {
		if g.CIDR == "10.10.60.0/24" {
			haveVLAN = true
		}
		if g.ID == "g:other" {
			haveOverflow = true
		}
	}
	for _, n := range m.Nodes {
		nodeShown[n.ID] = true
	}
	if !haveVLAN {
		t.Error("10.10.60.0/24 lost its own box under show-all-private")
	}
	if haveOverflow {
		t.Error("show-all-private must not produce an 'other internal networks' bucket")
	}
	if !nodeShown["10.10.60.1"] || !nodeShown["10.10.60.2"] {
		t.Error("10.10.60 hosts not shown individually")
	}
}

// TestOverviewKeepsCrossVLANEdges guards the reported regression: after the
// group cap rose, per-VLAN aggregate + inferred-gateway nodes starved the
// element budget and trimOverviewEdges dropped the cross-VLAN dependencies
// first (they touch no retained host). Cross-group bundles are the story of
// a routed network and must survive.
func TestOverviewKeepsCrossVLANEdges(t *testing.T) {
	var nodes []graph.Node
	var edges []graph.Edge
	rank := 0
	add := func(ip, subnet string, composite float64) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: composite, Rank: rank}})
	}
	// 12 VLAN gateways get the top ranks (retained). Their client hosts rank
	// far lower and aggregate into "N other hosts".
	for v := 0; v < 12; v++ {
		add(fmt.Sprintf("10.0.%d.1", v), fmt.Sprintf("10.0.%d.0/24", v), 0.9)
	}
	for v := 0; v < 12; v++ {
		for h := 0; h < 40; h++ {
			add(fmt.Sprintf("10.0.%d.%d", v, h+10), fmt.Sprintf("10.0.%d.0/24", v), 0.02)
		}
	}
	// Filler: strong intra-VLAN edges among retained hosts in VLAN 0. These
	// out-rank the cross-VLAN bundles in trimming and consume the budget.
	for h := 10; h < 20; h++ {
		edges = append(edges, graph.Edge{
			Src: fmt.Sprintf("10.0.0.%d", h), Dst: "10.0.0.1",
			Port: 445, ConnCount: 9000,
		})
	}
	// Heavy cross-VLAN traffic between aggregated hosts of adjacent VLANs —
	// routed through the gateway in reality. None touch a retained host.
	for v := 0; v < 11; v++ {
		edges = append(edges, graph.Edge{
			Src: fmt.Sprintf("10.0.%d.30", v), Dst: fmt.Sprintf("10.0.%d.30", v+1),
			Port: 445, ConnCount: 5000,
		})
	}
	m := buildOverview(graph.Snapshot{Nodes: nodes, Edges: edges}, Options{GroupPrefix: 24}, nil, nil, 0)

	group := map[string]string{}
	for _, n := range m.Nodes {
		group[n.ID] = n.Group
	}
	cross := 0
	for _, e := range m.Edges {
		if gs, gd := group[e.Src], group[e.Dst]; gs != "" && gd != "" && gs != gd {
			cross++
		}
	}
	if cross == 0 {
		t.Fatalf("no cross-VLAN edges survived the overview (of %d edges) — the routed dependencies were trimmed", len(m.Edges))
	}
}

// TestOverviewDeclaredGateway: a declared-config gateway for a segment gets a
// "(declared)" gateway node carrying config evidence, and no inferred gateway
// is emitted for that same segment. Empty/nil DeclaredGateways leaves the
// overview byte-identical to today (regression on an existing fixture shape).
func TestOverviewDeclaredGateway(t *testing.T) {
	var nodes []graph.Node
	rank := 0
	add := func(ip, subnet string) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: 0.5, Rank: rank}})
	}
	// Two busy VLANs — enough hosts to force the condensed overview.
	for v := 0; v < 2; v++ {
		for h := 0; h < 60; h++ {
			add(fmt.Sprintf("10.0.%d.%d", v, h+1), fmt.Sprintf("10.0.%d.0/24", v))
		}
	}
	edges := []graph.Edge{{Src: "10.0.0.1", Dst: "10.0.1.1", Port: 445, ConnCount: 100}}
	snap := graph.Snapshot{Nodes: nodes, Edges: edges}

	// Router interface 10.0.0.254 is declared but never observed (no node).
	declared := map[string]string{"10.0.0.254": "core-rtr"}
	m := buildOverview(snap, Options{GroupPrefix: 24, DeclaredGateways: declared}, nil, nil, 999)

	seg := groupID("10.0.0.0/24")
	var declaredNode *MapNode
	for i := range m.Nodes {
		n := &m.Nodes[i]
		if n.Group == seg && n.Gateway && strings.Contains(n.Label, "(declared)") {
			declaredNode = n
		}
		if n.Group == seg && strings.Contains(n.Label, "(inferred)") {
			t.Errorf("inferred gateway %q not suppressed by declared config", n.ID)
		}
	}
	if declaredNode == nil {
		t.Fatalf("no declared gateway node for segment %s", seg)
	}
	if !hasEvidence(declaredNode.Evidence, "gateway declared by core-rtr config") {
		t.Errorf("declared gateway missing config evidence, got %v", declaredNode.Evidence)
	}

	// Regression: nil vs empty DeclaredGateways must yield identical node sets.
	a := nodeIDSet(buildOverview(snap, Options{GroupPrefix: 24}, nil, nil, 999))
	b := nodeIDSet(buildOverview(snap, Options{GroupPrefix: 24, DeclaredGateways: map[string]string{}}, nil, nil, 999))
	if !reflect.DeepEqual(a, b) {
		t.Errorf("empty DeclaredGateways changed the node set:\n nil=%v\n empty=%v", a, b)
	}
}

func TestDeclaredGatewaySurvivesFullBudget(t *testing.T) {
	seg := groupID("10.0.0.0/24")
	m := Model{Groups: []Group{{ID: seg, CIDR: "10.0.0.0/24"}}}
	for i := 0; i < config.MapTargetElements; i++ {
		m.Nodes = append(m.Nodes, MapNode{ID: fmt.Sprintf("noise-%d", i)})
	}
	m.addDeclaredGateways(map[string]string{"10.0.0.1": "core-rtr"}, func(string) string { return seg })
	for _, n := range m.Nodes {
		if n.Group == seg && n.Gateway && strings.Contains(n.Label, "(declared)") {
			return
		}
	}
	t.Fatal("declared gateway was dropped when the overview budget was full")
}

// TestOverviewDeclaredGatewayBadgesObservedHost: when the declared gateway IP
// is itself an observed, retained host, that node is badged in place (label
// suffix + config evidence) rather than duplicated by a synthetic node.
func TestOverviewDeclaredGatewayBadgesObservedHost(t *testing.T) {
	var nodes []graph.Node
	rank := 0
	add := func(ip, subnet string, composite float64) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: composite, Rank: rank}})
	}
	// The gateway host ranks top so it is retained as its own node.
	add("10.0.0.1", "10.0.0.0/24", 0.99)
	for h := 0; h < 60; h++ {
		add(fmt.Sprintf("10.0.0.%d", h+10), "10.0.0.0/24", 0.1)
		add(fmt.Sprintf("10.0.1.%d", h+10), "10.0.1.0/24", 0.1)
	}
	snap := graph.Snapshot{Nodes: nodes}
	declared := map[string]string{"10.0.0.1": "core-rtr"}
	m := buildOverview(snap, Options{GroupPrefix: 24, DeclaredGateways: declared}, nil, nil, 999)

	count := 0
	for _, n := range m.Nodes {
		if n.ID == "10.0.0.1" {
			count++
			if !n.Gateway || !strings.Contains(n.Label, "(declared)") {
				t.Errorf("observed gateway host not badged: gateway=%v label=%q", n.Gateway, n.Label)
			}
			if !hasEvidence(n.Evidence, "gateway declared by core-rtr config") {
				t.Errorf("observed gateway host missing config evidence, got %v", n.Evidence)
			}
		}
		if n.ID == groupID("10.0.0.0/24")+":gw" {
			t.Errorf("synthetic gateway duplicates the badged observed host")
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one node for the gateway IP, got %d", count)
	}
}

func nodeIDSet(m *Model) map[string]bool {
	s := map[string]bool{}
	for _, n := range m.Nodes {
		s[n.ID] = true
	}
	return s
}

func hasEvidence(ev []string, want string) bool {
	for _, e := range ev {
		if e == want {
			return true
		}
	}
	return false
}

func TestTrimOverviewEdgesDriftExempt(t *testing.T) {
	retained := map[string]bool{"10.0.0.1": true}
	var edges []MapEdge
	for i := 0; i < 10; i++ {
		edges = append(edges, MapEdge{
			Src: fmt.Sprintf("10.0.0.%d", 10+i), Dst: "10.0.0.1",
			Class: "web", Conns: int64(1000 - i),
		})
	}
	// Weakest possible edge, but drift-flagged: must survive any budget.
	edges = append(edges, MapEdge{Src: "10.9.9.9", Dst: "10.8.8.8", Class: "web", Conns: 1, Drift: "new"})

	got := trimOverviewEdges(edges, 3, retained, nil)
	if len(got) != 4 {
		t.Fatalf("kept %d edges, want 3 budgeted + 1 flagged", len(got))
	}
	driftKept := false
	for _, e := range got {
		if e.Drift == "new" {
			driftKept = true
		}
	}
	if !driftKept {
		t.Error("drift-flagged edge was trimmed; flagged edges are budget-exempt")
	}
	if got2 := trimOverviewEdges(edges, -5, retained, nil); len(got2) != 1 || got2[0].Drift != "new" {
		t.Errorf("negative budget must keep only flagged edges, got %d", len(got2))
	}
}
