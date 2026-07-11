package mapview

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func TestBuildServiceAuthority(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Hour)
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Hostnames: []string{"dns1.corp"},
				Roles: []graph.RoleAssertion{{Role: graph.RoleDNS, Confidence: 0.9}},
				Scores: graph.ScoreSet{Rank: 3}},
			{IP: "10.0.3.30"},
			{IP: "10.0.3.31"},
			{IP: "10.0.3.66"}, // scanner client, must not inflate the DNS provider's count
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				FirstSeen: t0, LastSeen: t1},
			{Src: "10.0.3.31", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				FirstSeen: t0.Add(30 * time.Minute), LastSeen: t1},
			// port-only attempt must not count as a client of the DNS provider
			{Src: "10.0.3.66", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidencePortOnly,
				FirstSeen: t0, LastSeen: t0},
			// non-sensitive port must be excluded entirely
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 8080, Evidence: graph.EvidenceProtocolConfirmed,
				FirstSeen: t0, LastSeen: t1},
			// broadcast destination must be excluded
			{Src: "10.0.3.30", Dst: "255.255.255.255", Port: 67, Evidence: graph.EvidenceResponderConfirmed,
				FirstSeen: t0, LastSeen: t1},
		},
	}
	rows := BuildServiceAuthority(snap)
	if len(rows) != 1 {
		t.Fatalf("want 1 provider row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.IP != "10.0.1.11" || r.Hostname != "dns1.corp" || r.Role != graph.RoleDNS ||
		r.Service != "dns" || r.Port != 53 || r.Clients != 2 || r.Rank != 3 {
		t.Errorf("bad row: %+v", r)
	}
	if r.Evidence != graph.EvidenceProtocolConfirmed {
		t.Errorf("Evidence = %q, want protocol-confirmed", r.Evidence)
	}
	if !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t1) {
		t.Errorf("bad first/last seen: %v / %v", r.FirstSeen, r.LastSeen)
	}
}

func TestBuildServiceAuthorityStrongestEvidenceWins(t *testing.T) {
	// Same provider/port aggregated from a mix of evidence tiers must report
	// the strongest tier actually observed, not the weakest or the last one.
	snap := graph.Snapshot{
		Nodes: []graph.Node{{IP: "10.0.1.20"}, {IP: "10.0.3.30"}, {IP: "10.0.3.31"}},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceResponderConfirmed},
			{Src: "10.0.3.31", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	rows := BuildServiceAuthority(snap)
	if len(rows) != 1 || rows[0].Evidence != graph.EvidenceProtocolConfirmed {
		t.Fatalf("want protocol-confirmed to win, got %+v", rows)
	}
}

func TestBuildServiceAuthoritySortOrder(t *testing.T) {
	// Clients desc, then IP, then Port — same convention as snapshot.NewProvider.
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11"}, {IP: "10.0.1.20"},
			{IP: "10.0.3.30"}, {IP: "10.0.3.31"}, {IP: "10.0.3.32"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.3.30", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceResponderConfirmed},
			{Src: "10.0.3.31", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceResponderConfirmed},
			{Src: "10.0.3.32", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceResponderConfirmed},
		},
	}
	rows := BuildServiceAuthority(snap)
	if len(rows) != 2 || rows[0].IP != "10.0.1.20" || rows[0].Clients != 3 || rows[1].IP != "10.0.1.11" {
		t.Fatalf("bad sort order: %+v", rows)
	}
}
