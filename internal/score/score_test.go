package score

import (
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func TestScoreAttachesTerrainEvidence(t *testing.T) {
	edges := []graph.Edge{
		{Src: "10.0.1.10", Dst: "10.0.3.10", Port: 88, ConnCount: 10},
		{Src: "10.0.2.10", Dst: "10.0.3.10", Port: 88, ConnCount: 10},
		{Src: "10.0.3.10", Dst: "10.0.4.10", Port: 443, ConnCount: 10},
	}
	m := graph.Build(edges)
	Score(m)

	hub := m.Nodes["10.0.3.10"]
	why := strings.Join(hub.TerrainEvidence, "\n")
	if len(hub.TerrainEvidence) == 0 || hub.TerrainEvidence[0] != "2 distinct hosts depend on it for critical services" {
		t.Errorf("strongest terrain evidence = %q, want critical dependents first", hub.TerrainEvidence)
	}
	if !strings.Contains(why, "chokepoint:") {
		t.Errorf("terrain evidence = %q, want chokepoint rationale", why)
	}
	if !strings.Contains(why, "2 distinct hosts depend") {
		t.Errorf("terrain evidence = %q, want dependent-host rationale", why)
	}
}

// TestScoreExcludesBroadcastMulticast: broadcast/multicast destinations soak
// up traffic from every host (DHCP, mDNS, IGMP) but are not terrain — they
// must never outrank a real server, and must not compress real nodes'
// normalized component scores.
func TestScoreExcludesBroadcastMulticast(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var edges []graph.Edge
	add := func(src, dst string, port uint16, conns int64) {
		edges = append(edges, graph.Edge{
			Src: src, Dst: dst, Port: port, ConnCount: conns,
			FirstSeen: t0, LastSeen: t0.Add(time.Hour),
		})
	}
	// Every client hammers broadcast/multicast harder than the real server.
	for i := 0; i < 10; i++ {
		src := clientIP(i)
		add(src, "255.255.255.255", 67, 5000)
		add(src, "224.0.0.251", 5353, 5000)
		add(src, "10.0.1.10", 88, 100)
		add(src, "10.0.1.10", 53, 100)
	}
	m := graph.Build(edges)
	Score(m)

	byIP := map[string]*graph.Node{}
	for _, n := range m.SortedNodes() {
		byIP[n.IP] = n
	}
	server := byIP["10.0.1.10"]
	if server.Scores.Rank != 1 {
		t.Errorf("real server rank = %d, want 1", server.Scores.Rank)
	}
	for _, junk := range []string{"255.255.255.255", "224.0.0.251"} {
		n := byIP[junk]
		if n.Scores.Composite != 0 {
			t.Errorf("%s composite = %v, want 0 (not terrain)", junk, n.Scores.Composite)
		}
		if n.Scores.Rank <= server.Scores.Rank {
			t.Errorf("%s rank %d must be worse than the real server's %d", junk, n.Scores.Rank, server.Scores.Rank)
		}
	}
	// Normalization must run over terrain only: with the broadcast noise
	// excluded, the server holds the max critical in-degree and its
	// composite must reflect a full dependency component, not a compressed
	// fraction of the broadcast node's client count.
	if server.Scores.Composite <= 0.5 {
		t.Errorf("server composite = %v — broadcast noise still compresses terrain normalization", server.Scores.Composite)
	}
}

func TestPortOnlyEdgesDoNotScore(t *testing.T) {
	confirmed := graph.Edge{Src: "10.0.0.1", Dst: "10.0.0.2", Port: 88, ConnCount: 50, Evidence: graph.EvidenceResponderConfirmed}
	scanned := graph.Edge{Src: "10.0.0.3", Dst: "10.0.0.4", Port: 88, ConnCount: 50, Evidence: graph.EvidencePortOnly}
	m := graph.Build([]graph.Edge{confirmed, scanned})
	Score(m)
	if m.Nodes["10.0.0.4"].Scores.DependencyInDegree != 0 {
		t.Errorf("scanned dst critical in-degree = %d, want 0", m.Nodes["10.0.0.4"].Scores.DependencyInDegree)
	}
	if m.Nodes["10.0.0.2"].Scores.DependencyInDegree != 1 {
		t.Errorf("confirmed dst critical in-degree = %d, want 1", m.Nodes["10.0.0.2"].Scores.DependencyInDegree)
	}
	if m.Nodes["10.0.0.2"].Scores.Composite <= m.Nodes["10.0.0.4"].Scores.Composite {
		t.Error("confirmed responder must outscore scanned responder")
	}
}

func clientIP(i int) string {
	return []string{
		"10.0.2.30", "10.0.2.31", "10.0.2.32", "10.0.2.33", "10.0.2.34",
		"10.0.3.30", "10.0.3.31", "10.0.3.32", "10.0.3.33", "10.0.3.34",
	}[i]
}
