package mission

import (
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func testSnapshot() graph.Snapshot {
	return graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.1", Scores: graph.ScoreSet{Rank: 1, Composite: 0.9}}, // mission system
			{IP: "10.0.1.2", Scores: graph.ScoreSet{Rank: 5, Composite: 0.4}}, // 1 hop (depends on .1)
			{IP: "10.0.1.3", Scores: graph.ScoreSet{Rank: 8, Composite: 0.2}}, // 2 hops (via .2)
			{IP: "10.0.9.9", Scores: graph.ScoreSet{Rank: 2, Composite: 0.8}}, // unrelated, high global rank
		},
		Edges: []graph.Edge{
			{Src: "10.0.1.2", Dst: "10.0.1.1", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.3", Dst: "10.0.1.2", Port: 445, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.9.9", Dst: "10.0.9.9", Port: 80, Evidence: graph.EvidenceProtocolConfirmed}, // self-loop, ignored
		},
	}
}

func TestComputeInScopeAndNeighbors(t *testing.T) {
	scores := Compute(testSnapshot(), map[string]bool{"10.0.1.1": true})
	byIP := map[string]Score{}
	for _, s := range scores {
		byIP[s.IP] = s
	}
	if !byIP["10.0.1.1"].InScope || byIP["10.0.1.1"].Depth != 0 {
		t.Errorf("10.0.1.1 (scope) = %+v", byIP["10.0.1.1"])
	}
	if byIP["10.0.1.2"].InScope || byIP["10.0.1.2"].Depth != 1 {
		t.Errorf("10.0.1.2 (1 hop) = %+v", byIP["10.0.1.2"])
	}
	if byIP["10.0.1.3"].InScope || byIP["10.0.1.3"].Depth != 2 {
		t.Errorf("10.0.1.3 (2 hops) = %+v", byIP["10.0.1.3"])
	}
	if _, ok := byIP["10.0.9.9"]; ok {
		t.Errorf("unrelated node 10.0.9.9 must not appear in mission scope at all, got %+v", byIP["10.0.9.9"])
	}
}

func TestComputeMissionScoreDecaysWithDepth(t *testing.T) {
	scores := Compute(testSnapshot(), map[string]bool{"10.0.1.1": true})
	byIP := map[string]Score{}
	for _, s := range scores {
		byIP[s.IP] = s
	}
	if byIP["10.0.1.1"].MissionScore != 1.0 {
		t.Errorf("in-scope MissionScore = %v, want 1.0", byIP["10.0.1.1"].MissionScore)
	}
	if byIP["10.0.1.2"].MissionScore <= byIP["10.0.1.3"].MissionScore {
		t.Errorf("closer node must score higher: .2=%v .3=%v", byIP["10.0.1.2"].MissionScore, byIP["10.0.1.3"].MissionScore)
	}
}

func TestComputeNeverMutatesGlobalScores(t *testing.T) {
	snap := testSnapshot()
	original := snap.Nodes[0].Scores
	Compute(snap, map[string]bool{"10.0.1.1": true})
	if snap.Nodes[0].Scores != original {
		t.Errorf("Compute must not mutate the snapshot's canonical Scores: got %+v, want %+v", snap.Nodes[0].Scores, original)
	}
}

func TestComputeRespectsMaxDepth(t *testing.T) {
	// A 4th node chained beyond MaxDepth must not appear at all.
	snap := testSnapshot()
	snap.Nodes = append(snap.Nodes, graph.Node{IP: "10.0.1.4", Scores: graph.ScoreSet{Rank: 9}})
	snap.Edges = append(snap.Edges, graph.Edge{Src: "10.0.1.4", Dst: "10.0.1.3", Port: 22, Evidence: graph.EvidenceResponderConfirmed})
	snap.Nodes = append(snap.Nodes, graph.Node{IP: "10.0.1.5", Scores: graph.ScoreSet{Rank: 10}})
	snap.Edges = append(snap.Edges, graph.Edge{Src: "10.0.1.5", Dst: "10.0.1.4", Port: 22, Evidence: graph.EvidenceResponderConfirmed})
	scores := Compute(snap, map[string]bool{"10.0.1.1": true})
	for _, s := range scores {
		if s.Depth > MaxDepth {
			t.Errorf("node %s at depth %d exceeds MaxDepth %d, should have been excluded", s.IP, s.Depth, MaxDepth)
		}
	}
}

func TestComputeIgnoresPortOnlyEdges(t *testing.T) {
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.1"}, {IP: "10.0.1.2"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.1.2", Dst: "10.0.1.1", Port: 445, Evidence: graph.EvidencePortOnly},
		},
	}
	scores := Compute(snap, map[string]bool{"10.0.1.1": true})
	if len(scores) != 1 {
		t.Fatalf("port-only edge must not connect a neighbor into scope, got %+v", scores)
	}
}

func TestComputeIgnoresScopeIPNotInSnapshot(t *testing.T) {
	// An operator typo or decommissioned host in --scope must not silently
	// "succeed" with a report containing only the phantom IP at depth 0.
	scores := Compute(testSnapshot(), map[string]bool{"10.0.99.99": true})
	if len(scores) != 0 {
		t.Errorf("scope IP absent from the snapshot must contribute nothing, got %+v", scores)
	}
}

func TestComputeMixedKnownAndUnknownScope(t *testing.T) {
	// A real scope IP still works even when another scope IP is a typo.
	scores := Compute(testSnapshot(), map[string]bool{"10.0.1.1": true, "10.0.99.99": true})
	found := false
	for _, s := range scores {
		if s.IP == "10.0.99.99" {
			t.Errorf("phantom scope IP must not appear in results: %+v", scores)
		}
		if s.IP == "10.0.1.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("real scope IP must still be scored: %+v", scores)
	}
}
