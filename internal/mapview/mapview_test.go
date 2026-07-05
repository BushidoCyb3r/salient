package mapview_test

import (
	"fmt"
	"net/netip"
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
	snap := largeFixture()
	mm := mapview.Build(snap, mapview.Options{})
	if !mm.Overview {
		t.Fatal("large unfocused map must build in overview mode")
	}
	// The segment-flow overview trades the old 60-element target for faithful
	// per-VLAN boxes, but must still be far smaller than the raw graph.
	if got := mm.Elements(); got >= len(snap.Nodes) {
		t.Fatalf("overview has %d elements, not smaller than %d raw nodes", got, len(snap.Nodes))
	}
	if !hasOverviewFinding(mm.Findings) {
		t.Fatal("overview does not explain that the map was condensed")
	}
}

// TestOverviewGroupsNeverCoarserThanSixteen guards the reported bug: overview
// coarsening produced supernet labels like "10.16.0.0/12" that name no real
// segment the operator runs (their hosts are 10.18.61.x). Group boxes must
// stay at /16 or finer; excess collapses into the honest "other" bucket.
func TestOverviewGroupsNeverCoarserThanSixteen(t *testing.T) {
	mm := mapview.Build(largeFixture(), mapview.Options{})
	if !mm.Overview {
		t.Fatal("large snapshot should build in overview mode")
	}
	for _, g := range mm.Groups {
		if g.CIDR == "" {
			continue // "other"/"external" aggregate boxes carry no CIDR
		}
		p, err := netip.ParsePrefix(g.CIDR)
		if err != nil {
			t.Fatalf("group CIDR %q does not parse: %v", g.CIDR, err)
		}
		if p.Bits() < 16 {
			t.Errorf("group %q is coarser than /16 — a supernet address that names no real network", g.CIDR)
		}
	}
}

// TestOverviewPerSegmentTopHosts: each VLAN box shows at most its top-N hosts;
// the rest of that segment collapse into one "N more hosts" chip whose members
// are recoverable. A busy segment cannot starve a quiet one.
func TestOverviewPerSegmentTopHosts(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var snap graph.Snapshot
	rank := 0
	add := func(ip, subnet string, comp float64) {
		rank++
		snap.Nodes = append(snap.Nodes, graph.Node{IP: ip, Subnet: subnet,
			FirstSeen: t0, LastSeen: t0.Add(time.Hour),
			Scores: graph.ScoreSet{Composite: comp, Rank: rank}})
	}
	// One busy VLAN with 12 hosts …
	for h := 0; h < 12; h++ {
		add(fmt.Sprintf("10.1.1.%d", h+1), "10.1.1.0/24", 1.0-float64(h)*0.01)
	}
	// … and 30 quiet VLANs so the map goes to overview and the busy VLAN would
	// have eaten a global top-N.
	for v := 0; v < 30; v++ {
		for h := 0; h < 4; h++ {
			add(fmt.Sprintf("10.2.%d.%d", v, h+1), fmt.Sprintf("10.2.%d.0/24", v), 0.3)
		}
	}
	mm := mapview.Build(snap, mapview.Options{})
	if !mm.Overview {
		t.Fatal("expected overview mode")
	}

	// The busy VLAN shows exactly MapSegmentTopHosts individual hosts + one
	// "N more hosts" chip for the remaining 7.
	busyIndividual, busyChip := 0, 0
	for _, n := range mm.Nodes {
		if strings.HasPrefix(n.ID, "10.1.1.") && n.AggCount == 0 {
			busyIndividual++
		}
		if n.AggCount == 12-config.MapSegmentTopHosts && strings.Contains(n.Label, "more hosts") {
			busyChip++
		}
	}
	if busyIndividual != config.MapSegmentTopHosts {
		t.Errorf("busy VLAN shows %d individual hosts, want %d", busyIndividual, config.MapSegmentTopHosts)
	}
	if busyChip != 1 {
		t.Errorf("busy VLAN has %d 'more hosts' chips, want 1", busyChip)
	}

	// A quiet VLAN's hosts (≤ top-N) all show individually — never blobbed away
	// by a global budget.
	quietShown := 0
	for _, n := range mm.Nodes {
		if strings.HasPrefix(n.ID, "10.2.0.") && n.AggCount == 0 {
			quietShown++
		}
	}
	if quietShown != 4 {
		t.Errorf("quiet VLAN 10.2.0.0/24 shows %d hosts, want all 4", quietShown)
	}

	// Every collapsed host is recoverable via AggMembers.
	for _, n := range mm.Nodes {
		if n.AggCount > 0 && len(mm.AggMembers[n.ID]) != n.AggCount {
			t.Errorf("aggregate %s: %d members, AggCount=%d", n.ID, len(mm.AggMembers[n.ID]), n.AggCount)
		}
	}

	// Small maps keep the detailed pipeline untouched.
	if small := mapview.Build(fixture(t), mapview.Options{}); small.Overview {
		t.Error("small map must not switch to overview mode")
	}
	// Focus keeps the detailed pipeline even on a large snapshot.
	if focused := mapview.Build(largeFixture(), mapview.Options{Focus: "10.0.0.0/24"}); focused.Overview {
		t.Error("focused map must not switch to overview mode")
	}
}

// largeInternetFixture mirrors the real homelab scan: a small internal
// network plus thousands of public peers pulled in by outbound traffic,
// with multicast/broadcast noise ranked into the top 20.
func largeInternetFixture() graph.Snapshot {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var snap graph.Snapshot
	snap.Meta = graph.SnapshotMeta{Window: "336h", ClusterName: "test"}
	rank := 0
	addNode := func(ip, subnet string, composite float64) {
		rank++
		snap.Nodes = append(snap.Nodes, graph.Node{
			IP: ip, Subnet: subnet, FirstSeen: t0, LastSeen: t0.Add(time.Hour),
			Scores: graph.ScoreSet{Composite: composite, Rank: rank},
		})
	}
	// Ranks 1-8: real internal terrain across two /16s.
	for i := 0; i < 4; i++ {
		addNode(fmt.Sprintf("10.10.40.%d", i+1), "10.10.40.0/24", 0.9)
		addNode(fmt.Sprintf("10.18.61.%d", i+1), "10.18.61.0/24", 0.9)
	}
	// Ranks 9-10: multicast + broadcast noise scored into the top block.
	addNode("224.0.0.251", "224.0.0.0/24", 0.8)
	addNode("255.255.255.255", "255.255.255.0/24", 0.8)
	// Remaining internal hosts.
	for i := 0; i < 20; i++ {
		addNode(fmt.Sprintf("10.10.40.%d", 100+i), "10.10.40.0/24", 0.3)
	}
	// Thousands of public peers: 300 /24s across many /8s, ten hosts each,
	// mid composite so they stay individually visible in the detailed map
	// (mirroring the real scan's hundreds of classified public web servers).
	for i := 0; i < 3000; i++ {
		s := i / 10
		subnet := fmt.Sprintf("%d.%d.%d.0/24", 43+(s%40), s%100, s/100)
		addNode(fmt.Sprintf("%d.%d.%d.%d", 43+(s%40), s%100, s/100, 10+i%10), subnet, 0.5)
	}
	for _, n := range snap.Nodes[1:] {
		snap.Edges = append(snap.Edges, graph.Edge{
			Src: n.IP, Dst: "10.10.40.1", Port: 443, ConnCount: 50,
			FirstSeen: t0, LastSeen: t0.Add(time.Hour),
		})
	}
	return snap
}

func TestOverviewInternetHeavySnapshot(t *testing.T) {
	snap := largeInternetFixture()
	mm := mapview.Build(snap, mapview.Options{})
	if !mm.Overview {
		t.Fatal("expected overview mode")
	}
	byID := map[string]mapview.MapNode{}
	for _, n := range mm.Nodes {
		byID[n.ID] = n
	}
	// Internal terrain groups must survive; public space must not own them.
	groupCIDRs := map[string]bool{}
	for _, g := range mm.Groups {
		groupCIDRs[g.CIDR] = true
		if g.CIDR != "" && !strings.HasPrefix(g.CIDR, "10.") && g.ID != "g:external" {
			t.Errorf("public space must collapse into the external group, found group %q", g.CIDR)
		}
	}
	if _, ok := byID["10.10.40.1"]; !ok {
		t.Error("top-ranked internal host missing from overview")
	}
	if _, ok := byID["10.18.61.1"]; !ok {
		t.Error("top-ranked internal host in second enclave missing from overview")
	}
	// Multicast/broadcast are not hosts and must never be individually shown.
	for _, ip := range []string{"224.0.0.251", "255.255.255.255"} {
		if _, ok := byID[ip]; ok {
			t.Errorf("%s must be aggregated, not shown as terrain", ip)
		}
	}
	// The external aggregate carries the public peers.
	ext, ok := byID["g:external:clients"]
	if !ok || ext.AggCount < 3000 {
		t.Errorf("external aggregate = %+v, want >=3000 public peers", ext)
	}
	if got := mm.Elements(); got > config.MapTargetElements {
		t.Errorf("overview has %d elements, target <= %d", got, config.MapTargetElements)
	}
}

func TestFocusPrivatePublicKeywords(t *testing.T) {
	snap := largeInternetFixture()

	// private: internal terrain only, no external group or public nodes.
	priv := mapview.Build(snap, mapview.Options{Focus: "private"})
	for _, g := range priv.Groups {
		if g.ID == "g:external" {
			t.Error("--focus private must exclude the external group")
		}
	}
	for _, n := range priv.Nodes {
		if strings.HasPrefix(n.ID, "43.") || strings.HasPrefix(n.ID, "44.") {
			t.Errorf("--focus private leaked public node %s", n.ID)
		}
	}
	found := false
	for _, n := range priv.Nodes {
		if n.ID == "10.10.40.1" {
			found = true
		}
	}
	if !found {
		t.Error("--focus private must keep internal terrain")
	}

	// public: no individual internal hosts; oversized result still condenses.
	pub := mapview.Build(snap, mapview.Options{Focus: "public"})
	for _, n := range pub.Nodes {
		if strings.HasPrefix(n.ID, "10.") {
			t.Errorf("--focus public leaked internal node %s", n.ID)
		}
	}
	if !pub.Overview {
		t.Error("oversized --focus public map must still condense to an overview")
	}
	if got := pub.Elements(); got > config.MapTargetElements {
		t.Errorf("--focus public overview has %d elements, target <= %d", got, config.MapTargetElements)
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
	if len(gws) == 0 || len(gws) > config.MapSegmentMaxGroups {
		t.Fatalf("overview retained %d gateways, want 1..%d strongest", len(gws), config.MapSegmentMaxGroups)
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
	silentFinding := false
	for _, f := range mm.Findings {
		if strings.Contains(f, "documented assets produced no observed traffic") {
			silentFinding = true
		}
	}
	if !silentFinding {
		t.Errorf("silent-asset finding missing: %v", mm.Findings)
	}
	// In the segment-flow overview every reconcile-flagged host is retained
	// individually (drift/overlay marks are never aggregated), so the map must
	// stay smaller than the raw graph but is no longer bounded by a global top-N.
	if got := len(mm.Nodes); got >= len(snap.Nodes) {
		t.Errorf("overview node count %d not smaller than %d raw nodes", got, len(snap.Nodes))
	}
}

// TestDetailedBuildRetainAllPrivateShowsEveryClient: with RetainAllPrivate
// (drill-in / show-all-private) the detailed build must not collapse low-value
// clients into an "N workstations" aggregate — every host is individual.
func TestDetailedBuildRetainAllPrivateShowsEveryClient(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var snap graph.Snapshot
	for i := 0; i < 8; i++ {
		snap.Nodes = append(snap.Nodes, graph.Node{
			IP: fmt.Sprintf("10.10.40.%d", i+2), Subnet: "10.10.40.0/24",
			FirstSeen: t0, LastSeen: t0.Add(time.Hour),
			Scores: graph.ScoreSet{Composite: 0.01, Rank: i + 1}, // below ClientAggMaxComposite
		})
	}
	// Default: low-value clients aggregate into "N workstations".
	base := mapview.Build(snap, mapview.Options{})
	agg := false
	for _, n := range base.Nodes {
		if n.AggCount > 0 {
			agg = true
		}
	}
	if !agg {
		t.Fatal("baseline should aggregate low-value clients")
	}
	// RetainAllPrivate: every client shown individually, no aggregate.
	full := mapview.Build(snap, mapview.Options{RetainAllPrivate: true})
	shown := 0
	for _, n := range full.Nodes {
		if n.AggCount > 0 {
			t.Errorf("RetainAllPrivate must not aggregate: found %s (%d)", n.ID, n.AggCount)
		}
		if strings.HasPrefix(n.ID, "10.10.40.") {
			shown++
		}
	}
	if shown != 8 {
		t.Errorf("show %d clients, want all 8 individual", shown)
	}
}

// TestOperatorSegmentsSplitAndMerge: operator-declared subnets override the
// auto-/24 grouping — a /24 splits into /25s, and undeclared IPs still auto-/24.
func TestOperatorSegmentsSplitAndMerge(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	mk := func(ip string) graph.Node {
		return graph.Node{IP: ip, Subnet: graph.Subnet(ip), FirstSeen: t0, LastSeen: t0,
			Scores: graph.ScoreSet{Composite: 0.5, Rank: 1}}
	}
	snap := graph.Snapshot{Nodes: []graph.Node{
		mk("10.10.40.10"), mk("10.10.40.20"), // lower /25
		mk("10.10.40.130"), mk("10.10.40.140"), // upper /25
		mk("10.99.0.5"), mk("10.99.0.6"), // undeclared → auto /24
	}}
	opts := mapview.Options{Segments: []mapview.Segment{
		{CIDR: "10.10.40.0/25", Name: "Servers"},
		{CIDR: "10.10.40.128/25", Name: "Workstations"},
	}}
	m := mapview.Build(snap, opts)

	byIP := map[string]string{}
	for _, n := range m.Nodes {
		byIP[n.ID] = n.Group
	}
	if byIP["10.10.40.10"] != "g:10.10.40.0/25" {
		t.Errorf("10.10.40.10 group = %q, want the /25 override", byIP["10.10.40.10"])
	}
	if byIP["10.10.40.130"] != "g:10.10.40.128/25" {
		t.Errorf("10.10.40.130 group = %q, want the upper /25", byIP["10.10.40.130"])
	}
	if byIP["10.10.40.10"] == byIP["10.10.40.130"] {
		t.Error("the /24 was not split into two /25 segments")
	}
	if byIP["10.99.0.5"] != "g:10.99.0.0/24" {
		t.Errorf("undeclared host group = %q, want auto /24 fallback", byIP["10.99.0.5"])
	}
	// The operator name rides the box label.
	var named bool
	for _, g := range m.Groups {
		if g.CIDR == "10.10.40.0/25" && strings.Contains(g.Label, "Servers") {
			named = true
		}
	}
	if !named {
		t.Error("operator segment name missing from group label")
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

func TestBuildAttachesMACAndVendor(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	snap := graph.Snapshot{
		Nodes: []graph.Node{{
			IP: "10.0.0.1", Subnet: "10.0.0.0/24", MAC: "24:5a:4c:11:22:33",
			FirstSeen: t0, LastSeen: t0, Scores: graph.ScoreSet{Composite: 0.9, Rank: 1},
		}},
	}
	mm := mapview.Build(snap, mapview.Options{})
	for _, n := range mm.Nodes {
		if n.ID == "10.0.0.1" {
			if n.MAC != "24:5a:4c:11:22:33" || n.Vendor != "Ubiquiti" {
				t.Fatalf("MAC/vendor not surfaced: mac=%q vendor=%q", n.MAC, n.Vendor)
			}
			return
		}
	}
	t.Fatal("node 10.0.0.1 missing from model")
}

func TestBuildAttachesServices(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	node := func(ip string) graph.Node {
		return graph.Node{IP: ip, Subnet: "10.0.0.0/24", FirstSeen: t0, LastSeen: t0,
			Scores: graph.ScoreSet{Composite: 0.9, Rank: 1}}
	}
	snap := graph.Snapshot{
		Nodes: []graph.Node{node("10.0.0.1"), node("10.0.0.2"), node("10.0.0.3")},
		Edges: []graph.Edge{
			{Src: "10.0.0.2", Dst: "10.0.0.1", Port: 443, ConnCount: 100},
			{Src: "10.0.0.2", Dst: "10.0.0.1", Port: 22, ConnCount: 100},
			{Src: "10.0.0.3", Dst: "10.0.0.1", Port: 443, ConnCount: 100},   // dup https — dedupe
			{Src: "10.0.0.2", Dst: "10.0.0.3", Port: 49200, ConnCount: 100}, // unknown port — no name
		},
	}
	mm := mapview.Build(snap, mapview.Options{})
	byID := map[string]mapview.MapNode{}
	for _, n := range mm.Nodes {
		byID[n.ID] = n
	}
	// Port-sorted: 22 (ssh) before 443 (https).
	if got := byID["10.0.0.1"].Services; len(got) != 2 || got[0] != "ssh" || got[1] != "https" {
		t.Errorf("Services(10.0.0.1) = %v, want [ssh https]", got)
	}
	if got := byID["10.0.0.3"].Services; got != nil {
		t.Errorf("Services(10.0.0.3) = %v, want nil (unknown port only)", got)
	}
}

func TestOverviewAggMembersCarryServices(t *testing.T) {
	snap := largeFixture()
	snap.Edges = append(snap.Edges, graph.Edge{Src: snap.Nodes[0].IP, Dst: snap.Nodes[len(snap.Nodes)-1].IP, Port: 631, ConnCount: 5})
	mm := mapview.Build(snap, mapview.Options{})
	if !mm.Overview {
		t.Fatal("expected overview build")
	}
	target := snap.Nodes[len(snap.Nodes)-1].IP
	found := false
	for _, members := range mm.AggMembers {
		for _, m := range members {
			if m.ID == target {
				found = true
				if len(m.Services) == 0 || m.Services[0] != "ipp" {
					t.Errorf("aggregated member services = %v, want [ipp]", m.Services)
				}
			}
		}
	}
	if !found {
		// Target may have been retained instead of aggregated; then the
		// visible node must carry the service.
		for _, n := range mm.Nodes {
			if n.ID == target {
				found = true
				if len(n.Services) == 0 || n.Services[0] != "ipp" {
					t.Errorf("retained node services = %v, want [ipp]", n.Services)
				}
			}
		}
	}
	if !found {
		t.Fatalf("target %s missing from overview entirely", target)
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
	// AggMembers must list exactly the hosts each aggregate collapsed.
	for id, members := range mm.AggMembers {
		found := false
		for _, n := range mm.Nodes {
			if n.ID == id && n.AggCount == len(members) {
				found = true
			}
		}
		if !found {
			t.Errorf("aggregate %s has %d members but no matching node with that AggCount", id, len(members))
		}
	}
	if len(mm.AggMembers[agg.ID]) != agg.AggCount {
		t.Errorf("aggregate %s: %d members, AggCount=%d", agg.ID, len(mm.AggMembers[agg.ID]), agg.AggCount)
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
