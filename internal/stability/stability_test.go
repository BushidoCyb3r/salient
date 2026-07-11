package stability

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func snap(t time.Time, ranks map[string]int, roles map[string]graph.Role) graph.Snapshot {
	var nodes []graph.Node
	for ip, r := range ranks {
		n := graph.Node{IP: ip, Scores: graph.ScoreSet{Rank: r}}
		if role, ok := roles[ip]; ok {
			n.Roles = []graph.RoleAssertion{{Role: role, Confidence: 0.9}}
		}
		nodes = append(nodes, n)
	}
	return graph.Snapshot{Meta: graph.SnapshotMeta{CreatedAt: t}, Nodes: nodes}
}

func TestComputeStabilityPersistentNode(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snaps := []graph.Snapshot{
		snap(t0, map[string]int{"10.0.0.1": 1, "10.0.0.2": 2, "10.0.0.3": 3, "10.0.0.4": 4},
			map[string]graph.Role{"10.0.0.1": graph.RoleDNS}),
		snap(t0.Add(24*time.Hour), map[string]int{"10.0.0.1": 1, "10.0.0.2": 3, "10.0.0.3": 2, "10.0.0.4": 4},
			map[string]graph.Role{"10.0.0.1": graph.RoleDNS}),
		snap(t0.Add(48*time.Hour), map[string]int{"10.0.0.1": 2, "10.0.0.2": 1, "10.0.0.3": 3, "10.0.0.4": 4},
			map[string]graph.Role{"10.0.0.1": graph.RoleDNS}),
	}
	stats := Compute(snaps, 2)
	byIP := map[string]NodeStability{}
	for _, s := range stats {
		byIP[s.IP] = s
	}
	dns := byIP["10.0.0.1"]
	if dns.Occurrences != 3 {
		t.Errorf("10.0.0.1 Occurrences = %d, want 3", dns.Occurrences)
	}
	if dns.TopNOccurrences != 3 {
		t.Errorf("10.0.0.1 TopNOccurrences = %d, want 3 (rank<=2 every time)", dns.TopNOccurrences)
	}
	if dns.Classification != ClassPersistent {
		t.Errorf("10.0.0.1 Classification = %q, want persistent", dns.Classification)
	}
	if !dns.RoleConsistent {
		t.Error("10.0.0.1 RoleConsistent = false, want true (always DNSServer)")
	}
	// 4-node snapshots: rank 1 -> percentile 1.0, rank 4 -> percentile 0.0
	if dns.BestRankPercentile != 1.0 {
		t.Errorf("10.0.0.1 BestRankPercentile = %v, want 1.0", dns.BestRankPercentile)
	}
}

func TestComputeStabilityEmergingAndTransient(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snaps := []graph.Snapshot{
		snap(t0, map[string]int{"10.0.0.1": 1, "10.0.0.9": 2}, nil), // 10.0.0.9 only here
		snap(t0.Add(24*time.Hour), map[string]int{"10.0.0.1": 1}, nil),
		snap(t0.Add(48*time.Hour), map[string]int{"10.0.0.1": 1, "10.0.0.5": 2}, nil), // 10.0.0.5 only here
	}
	stats := Compute(snaps, 10)
	byIP := map[string]NodeStability{}
	for _, s := range stats {
		byIP[s.IP] = s
	}
	if byIP["10.0.0.9"].Classification != ClassTransient {
		t.Errorf("10.0.0.9 (in earliest, absent from latest) Classification = %q, want transient", byIP["10.0.0.9"].Classification)
	}
	if byIP["10.0.0.5"].Classification != ClassEmerging {
		t.Errorf("10.0.0.5 (absent from earliest, in latest) Classification = %q, want emerging", byIP["10.0.0.5"].Classification)
	}
	if byIP["10.0.0.1"].Classification != ClassPersistent {
		t.Errorf("10.0.0.1 (in all three) Classification = %q, want persistent", byIP["10.0.0.1"].Classification)
	}
}

func TestComputeStabilityRoleInconsistency(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snaps := []graph.Snapshot{
		snap(t0, map[string]int{"10.0.0.1": 1}, map[string]graph.Role{"10.0.0.1": graph.RoleDNS}),
		snap(t0.Add(24*time.Hour), map[string]int{"10.0.0.1": 1}, map[string]graph.Role{"10.0.0.1": graph.RoleWebServer}),
	}
	stats := Compute(snaps, 10)
	if len(stats) != 1 || stats[0].RoleConsistent {
		t.Errorf("expected RoleConsistent=false for a node whose role changed, got %+v", stats)
	}
}

func TestComputeStabilitySortsByCreatedAtRegardlessOfInputOrder(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	// Deliberately passed out of chronological order.
	snaps := []graph.Snapshot{
		snap(t0.Add(48*time.Hour), map[string]int{"10.0.0.1": 1, "10.0.0.5": 2}, nil),
		snap(t0, map[string]int{"10.0.0.1": 1, "10.0.0.9": 2}, nil),
		snap(t0.Add(24*time.Hour), map[string]int{"10.0.0.1": 1}, nil),
	}
	stats := Compute(snaps, 10)
	byIP := map[string]NodeStability{}
	for _, s := range stats {
		byIP[s.IP] = s
	}
	// Same expectations as TestComputeStabilityEmergingAndTransient — input
	// order must not change the earliest/latest determination.
	if byIP["10.0.0.9"].Classification != ClassTransient {
		t.Errorf("out-of-order input: 10.0.0.9 Classification = %q, want transient", byIP["10.0.0.9"].Classification)
	}
	if byIP["10.0.0.5"].Classification != ClassEmerging {
		t.Errorf("out-of-order input: 10.0.0.5 Classification = %q, want emerging", byIP["10.0.0.5"].Classification)
	}
}
