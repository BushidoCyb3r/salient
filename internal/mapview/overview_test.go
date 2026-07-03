package mapview

import (
	"fmt"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func nodesInSubnets(subnets []string) []graph.Node {
	var out []graph.Node
	for _, s := range subnets {
		out = append(out, graph.Node{Subnet: s})
	}
	return out
}

func TestOverviewPrefix(t *testing.T) {
	var spread, oneSixteen, multiEight []string
	for i := 0; i < 200; i++ {
		// 20 /16s with ten /24s each — exceeds the cap at every prefix, so
		// coarsening bottoms out at /16 and overflow merges into "other".
		spread = append(spread, fmt.Sprintf("10.%d.%d.0/24", i%20, i/20))
		// 200 /24s inside one /16 — /20 still yields 13 groups.
		oneSixteen = append(oneSixteen, fmt.Sprintf("10.99.%d.0/24", i))
	}
	for i := 0; i < 12; i++ {
		// 12 distinct /8s — never coarsens past /16; caller merges overflow.
		multiEight = append(multiEight, fmt.Sprintf("%d.0.0.0/24", 10+i*10))
	}
	cases := []struct {
		name    string
		subnets []string
		start   int
		want    int
	}{
		{"few subnets keep /24", []string{"10.0.1.0/24", "10.0.2.0/24"}, 24, 24},
		{"one /16 coarsens to /16", oneSixteen, 24, 16},
		{"spread /16s bottom out at /16", spread, 24, 16},
		{"explicit start skips finer prefixes", oneSixteen, 16, 16},
		{"multi-/8 bottoms out at /16", multiEight, 24, 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := overviewPrefix(nodesInSubnets(tc.subnets), tc.start, config.MapOverviewMaxGroups); got != tc.want {
				t.Errorf("overviewPrefix(start=%d) = %d, want %d", tc.start, got, tc.want)
			}
		})
	}
	// Determinism: same input, same answer, and group count at the chosen
	// prefix respects the cap whenever a satisfying prefix exists.
	nodes := nodesInSubnets(oneSixteen)
	p := overviewPrefix(nodes, 24, config.MapOverviewMaxGroups)
	if p2 := overviewPrefix(nodes, 24, config.MapOverviewMaxGroups); p2 != p {
		t.Fatalf("overviewPrefix not deterministic: %d vs %d", p, p2)
	}
	distinct := map[string]bool{}
	for _, n := range nodes {
		distinct[regroup(n.Subnet, p)] = true
	}
	if len(distinct) > config.MapOverviewMaxGroups {
		t.Errorf("chosen prefix /%d yields %d groups, cap %d", p, len(distinct), config.MapOverviewMaxGroups)
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
