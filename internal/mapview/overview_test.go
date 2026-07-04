package mapview

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
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
	if len(m.Groups) > config.MapOverviewMaxGroups {
		t.Errorf("%d groups, cap %d", len(m.Groups), config.MapOverviewMaxGroups)
	}
	if !other {
		t.Error("expected the overflow 'other internal networks' bucket")
	}
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

	got := trimOverviewEdges(edges, 3, retained)
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
	if got2 := trimOverviewEdges(edges, -5, retained); len(got2) != 1 || got2[0].Drift != "new" {
		t.Errorf("negative budget must keep only flagged edges, got %d", len(got2))
	}
}
