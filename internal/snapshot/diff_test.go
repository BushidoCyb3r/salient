package snapshot

import (
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func TestCompareDetectsRequiredDriftSignals(t *testing.T) {
	from := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.1", Scores: graph.ScoreSet{Rank: 1}, Roles: []graph.RoleAssertion{{Role: graph.RoleDNS}, {Role: graph.RoleWebServer}}},
			{IP: "10.0.0.2", Scores: graph.ScoreSet{Rank: 2}},
			{IP: "10.0.0.3", Scores: graph.ScoreSet{Rank: 3}},
		},
		Edges: []graph.Edge{
			{Src: "10.0.0.2", Dst: "10.0.0.1", Port: 53},
			{Src: "10.0.0.2", Dst: "10.0.0.3", Port: 445},
		},
	}
	to := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.1", Scores: graph.ScoreSet{Rank: 3}, Roles: []graph.RoleAssertion{{Role: graph.RoleDNS}, {Role: graph.RoleFileServer}}},
			{IP: "10.0.0.2", Scores: graph.ScoreSet{Rank: 1}},
			{IP: "10.0.0.4", Scores: graph.ScoreSet{Rank: 2}},
		},
		Edges: []graph.Edge{
			{Src: "10.0.0.4", Dst: "10.0.0.2", Port: 445},
		},
	}

	got := Compare(from, to, DiffOptions{RankDelta: 2, TopN: 2})
	if len(got.AppearedNodes) != 1 || got.AppearedNodes[0].IP != "10.0.0.4" {
		t.Fatalf("appeared nodes = %+v", got.AppearedNodes)
	}
	if len(got.DisappearedNodes) != 1 || got.DisappearedNodes[0].IP != "10.0.0.3" {
		t.Fatalf("disappeared nodes = %+v", got.DisappearedNodes)
	}
	if len(got.RankChanges) != 1 || got.RankChanges[0].IP != "10.0.0.1" || got.RankChanges[0].Delta != -2 {
		t.Fatalf("rank changes = %+v", got.RankChanges)
	}
	if len(got.NewEdgesToTop) != 1 || got.NewEdgesToTop[0].Src != "10.0.0.4" {
		t.Fatalf("new edges to top nodes = %+v", got.NewEdgesToTop)
	}
	if len(got.VanishedCriticalEdges) != 1 || got.VanishedCriticalEdges[0].Port != 53 {
		t.Fatalf("vanished critical edges = %+v", got.VanishedCriticalEdges)
	}
	if len(got.RoleChanges) != 1 ||
		!reflect.DeepEqual(got.RoleChanges[0].From, []graph.Role{graph.RoleDNS, graph.RoleWebServer}) ||
		!reflect.DeepEqual(got.RoleChanges[0].To, []graph.Role{graph.RoleDNS, graph.RoleFileServer}) {
		t.Fatalf("role changes = %+v", got.RoleChanges)
	}
}
