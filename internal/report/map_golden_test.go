package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
)

// mapFixture is a small, fixed snapshot exercising a real group, a sparse
// group, an aggregated client meta-node, an inferred gateway, and a blind
// spot — everything the map renderers need to draw.
func mapFixture() *mapview.Model {
	snap := graph.Snapshot{
		Meta: graph.SnapshotMeta{
			CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			Window:    "336h0m0s", ClusterName: "golden",
			ZeroCovCIDRs: []string{"10.0.99.0/24"},
		},
		Nodes: []graph.Node{
			{IP: "10.0.1.10", Subnet: "10.0.1.0/24", Roles: []graph.RoleAssertion{{Role: graph.RoleDC, Confidence: 0.8}},
				Scores: graph.ScoreSet{Rank: 1, Composite: 0.9}},
			{IP: "10.0.2.30", Subnet: "10.0.2.0/24", Roles: []graph.RoleAssertion{{Role: graph.RoleUnknown}},
				Scores: graph.ScoreSet{Rank: 2, Composite: 0.0}},
			{IP: "10.0.2.31", Subnet: "10.0.2.0/24", Roles: []graph.RoleAssertion{{Role: graph.RoleUnknown}},
				Scores: graph.ScoreSet{Rank: 3, Composite: 0.0}},
		},
		Edges: []graph.Edge{
			{Src: "10.0.2.30", Dst: "10.0.1.10", Port: 88, ConnCount: 500},
			{Src: "10.0.2.31", Dst: "10.0.1.10", Port: 88, ConnCount: 500},
		},
	}
	return mapview.Build(snap, mapview.Options{})
}

func TestSVGMapGolden(t *testing.T) {
	var b bytes.Buffer
	if err := SVGMap(&b, mapFixture()); err != nil {
		t.Fatal(err)
	}
	golden(t, "map.svg", b.Bytes())
}

func TestGraphMLMapGolden(t *testing.T) {
	var b bytes.Buffer
	if err := GraphMLMap(&b, mapFixture()); err != nil {
		t.Fatal(err)
	}
	golden(t, "map.graphml", b.Bytes())
}

func TestHTMLMapSelfContainedAndHasEvidence(t *testing.T) {
	var b bytes.Buffer
	if err := HTMLMap(&b, mapFixture()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"cytoscape(", "gateway (inferred)", "10.0.1.10", "possible blind spot"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML map missing %q", want)
		}
	}
	// No <script src=...> or <link href=...> to an external URL — the
	// libraries themselves may mention http:// in license comments, which is
	// fine; what must never happen is the page trying to fetch anything.
	if strings.Contains(out, `src="http`) || strings.Contains(out, `href="http`) {
		t.Error("HTML map loads an external resource — must be fully self-contained")
	}
}
