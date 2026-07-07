package score

import (
	"fmt"
	"math"
	"testing"

	"gonum.org/v1/gonum/graph/network"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// star-of-chains fixture: hub bridges several chains, so betweenness has a
// clear, known ordering (hub highest).
func chainGraph(chains, length int) *graph.Model {
	var edges []graph.Edge
	hub := "10.0.0.1"
	for c := 0; c < chains; c++ {
		prev := hub
		for i := 0; i < length; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", c+1, i+1)
			edges = append(edges, graph.Edge{Src: prev, Dst: ip, Port: 445, ConnCount: 10})
			prev = ip
		}
	}
	return graph.Build(edges)
}

func TestSampledBetweennessMatchesExactWithAllPivots(t *testing.T) {
	m := chainGraph(4, 5)
	g := m.Directed()
	exact := network.Betweenness(g)
	sampled := sampledBetweenness(g, 1<<20) // clamped to n: every node a pivot

	for _, n := range m.SortedNodes() {
		id, _ := m.ID(n.IP)
		if math.Abs(sampled[id]-exact[id]) > 1e-9 {
			t.Errorf("%s: sampled %v, exact %v", n.IP, sampled[id], exact[id])
		}
	}
}

func TestSampledBetweennessDeterministicAndSeparatesChokeFromLeaf(t *testing.T) {
	m := chainGraph(6, 8)
	g := m.Directed()
	a := sampledBetweenness(g, 8)
	b := sampledBetweenness(g, 8)
	for id, v := range a {
		if b[id] != v {
			t.Fatalf("non-deterministic: id %d %v vs %v", id, v, b[id])
		}
	}
	// Directed graph: chain leaves are never intermediates, chain heads carry
	// all paths from the hub into their chain (the hub itself is a pure
	// source, so its betweenness is legitimately zero).
	head, _ := m.ID("10.0.1.1")
	leaf, _ := m.ID("10.0.1.8")
	if a[leaf] != 0 {
		t.Errorf("leaf betweenness = %v, want 0", a[leaf])
	}
	if a[head] <= 0 {
		t.Errorf("chain-head betweenness = %v, want > 0", a[head])
	}
}
