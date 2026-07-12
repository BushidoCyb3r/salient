package snapshot

import (
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
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

func TestCompareNewProviders(t *testing.T) {
	base := graph.Snapshot{
		Nodes: []graph.Node{{IP: "10.0.0.1"}, {IP: "10.0.0.53", Scores: graph.ScoreSet{Rank: 1}}},
		Edges: []graph.Edge{{Src: "10.0.0.1", Dst: "10.0.0.53", Port: 53, Evidence: graph.EvidenceProtocolConfirmed}},
	}
	next := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.1"}, {IP: "10.0.0.2"},
			{IP: "10.0.0.53", Scores: graph.ScoreSet{Rank: 1}},
			{IP: "10.0.0.99", Scores: graph.ScoreSet{Rank: 40}}, // new low-rank host
		},
		Edges: []graph.Edge{
			{Src: "10.0.0.1", Dst: "10.0.0.53", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			// new low-rank DNS provider with two confirmed clients — the handoff gap #3 case
			{Src: "10.0.0.1", Dst: "10.0.0.99", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.0.2", Dst: "10.0.0.99", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			// port-only "provider" (scan) must not become a lead
			{Src: "10.0.0.1", Dst: "10.0.0.2", Port: 445, Evidence: graph.EvidencePortOnly},
			// broadcast DHCP noise must not become a lead
			{Src: "10.0.0.1", Dst: "255.255.255.255", Port: 67, Evidence: graph.EvidenceResponderConfirmed},
			// non-sensitive port must not become a lead
			{Src: "10.0.0.1", Dst: "10.0.0.2", Port: 8080, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	d := Compare(base, next, DiffOptions{TopN: 10, RankDelta: 5})
	if len(d.NewProviders) != 1 {
		t.Fatalf("want exactly 1 new provider, got %+v", d.NewProviders)
	}
	p := d.NewProviders[0]
	if p.IP != "10.0.0.99" || p.Port != 53 || p.Service != "dns" || p.Clients != 2 || !p.NewHost || p.Rank != 40 {
		t.Errorf("bad new provider: %+v", p)
	}
}

func TestCompareNewProvidersExistingHostAndSort(t *testing.T) {
	base := graph.Snapshot{
		// 10.0.0.50 is an existing node with no sensitive-service edges yet.
		Nodes: []graph.Node{{IP: "10.0.0.1"}, {IP: "10.0.0.50", Scores: graph.ScoreSet{Rank: 12}}},
		Edges: []graph.Edge{{Src: "10.0.0.1", Dst: "10.0.0.50", Port: 8080, Evidence: graph.EvidenceProtocolConfirmed}},
	}
	next := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.1"}, {IP: "10.0.0.2"}, {IP: "10.0.0.3"},
			{IP: "10.0.0.50", Scores: graph.ScoreSet{Rank: 12}},
			{IP: "10.0.0.60", Scores: graph.ScoreSet{Rank: 30}}, // brand-new host
		},
		Edges: []graph.Edge{
			// existing host 10.0.0.50 starts serving smb — 3 confirmed clients
			{Src: "10.0.0.1", Dst: "10.0.0.50", Port: 445, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.0.2", Dst: "10.0.0.50", Port: 445, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.0.3", Dst: "10.0.0.50", Port: 445, Evidence: graph.EvidenceProtocolConfirmed},
			// brand-new host 10.0.0.60 serves dns — 5 confirmed clients, should sort first
			{Src: "10.0.1.1", Dst: "10.0.0.60", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.2", Dst: "10.0.0.60", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.3", Dst: "10.0.0.60", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.4", Dst: "10.0.0.60", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.5", Dst: "10.0.0.60", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	d := Compare(base, next, DiffOptions{TopN: 10, RankDelta: 5})
	if len(d.NewProviders) != 2 {
		t.Fatalf("want exactly 2 new providers, got %+v", d.NewProviders)
	}
	first, second := d.NewProviders[0], d.NewProviders[1]
	if first.IP != "10.0.0.60" || first.Clients != 5 || !first.NewHost {
		t.Errorf("want higher-client new-host provider sorted first, got %+v", first)
	}
	if second.IP != "10.0.0.50" || second.Port != 445 || second.Service != "smb" || second.Clients != 3 || second.NewHost {
		t.Errorf("want existing-host provider sorted second with NewHost=false, got %+v", second)
	}
}

func TestCompareProviderDisplacementMigration(t *testing.T) {
	base := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.10"}, {IP: "10.0.0.20"}, // two DNS providers
			{IP: "10.0.1.1"}, {IP: "10.0.1.2"}, {IP: "10.0.1.3"},
		},
		Edges: []graph.Edge{
			// 3 clients use provider Y (10.0.0.20) for dns
			{Src: "10.0.1.1", Dst: "10.0.0.20", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.2", Dst: "10.0.0.20", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.3", Dst: "10.0.0.20", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	next := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.10", Scores: graph.ScoreSet{Rank: 5}}, {IP: "10.0.0.20"},
			{IP: "10.0.1.1"}, {IP: "10.0.1.2"}, {IP: "10.0.1.3"}, {IP: "10.0.1.4"},
		},
		Edges: []graph.Edge{
			// 2 of those 3 clients moved to provider X (10.0.0.10); one stayed with Y
			{Src: "10.0.1.1", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.2", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.1.3", Dst: "10.0.0.20", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			// a brand-new client (never used any dns provider before) also picks X
			{Src: "10.0.1.4", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	d := Compare(base, next, DiffOptions{TopN: 10, RankDelta: 5})
	if len(d.ProviderDisplacements) != 1 {
		t.Fatalf("want exactly 1 displacement entry (only the gaining provider X), got %+v", d.ProviderDisplacements)
	}
	pd := d.ProviderDisplacements[0]
	if pd.IP != "10.0.0.10" || pd.Port != 53 || pd.Service != "dns" || pd.ClientsAdded != 1 || pd.Rank != 5 {
		t.Fatalf("bad displacement entry: %+v", pd)
	}
	if len(pd.MigratedFrom) != 1 || pd.MigratedFrom[0].IP != "10.0.0.20" || pd.MigratedFrom[0].Port != 53 || pd.MigratedFrom[0].Clients != 2 {
		t.Fatalf("bad migration source: %+v", pd.MigratedFrom)
	}
}

func TestCompareProviderDisplacementNoChangeProducesNoEntry(t *testing.T) {
	base := graph.Snapshot{
		Nodes: []graph.Node{{IP: "10.0.0.10"}, {IP: "10.0.1.1"}},
		Edges: []graph.Edge{{Src: "10.0.1.1", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidenceProtocolConfirmed}},
	}
	next := graph.Snapshot{
		Nodes: []graph.Node{{IP: "10.0.0.10"}, {IP: "10.0.1.1"}},
		Edges: []graph.Edge{{Src: "10.0.1.1", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidenceProtocolConfirmed}},
	}
	d := Compare(base, next, DiffOptions{TopN: 10, RankDelta: 5})
	if len(d.ProviderDisplacements) != 0 {
		t.Fatalf("unchanged client set must produce no displacement entry, got %+v", d.ProviderDisplacements)
	}
}

func TestCompareProviderDisplacementExcludesPortOnlyEdges(t *testing.T) {
	base := graph.Snapshot{
		Nodes: []graph.Node{{IP: "10.0.0.10"}, {IP: "10.0.0.20"}, {IP: "10.0.1.1"}},
		Edges: []graph.Edge{{Src: "10.0.1.1", Dst: "10.0.0.20", Port: 53, Evidence: graph.EvidenceProtocolConfirmed}},
	}
	next := graph.Snapshot{
		Nodes: []graph.Node{{IP: "10.0.0.10"}, {IP: "10.0.0.20"}, {IP: "10.0.1.1"}, {IP: "10.0.9.9"}},
		Edges: []graph.Edge{
			{Src: "10.0.1.1", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			// scanner probe to X must not count as a client / inflate ClientsAdded
			{Src: "10.0.9.9", Dst: "10.0.0.10", Port: 53, Evidence: graph.EvidencePortOnly},
		},
	}
	d := Compare(base, next, DiffOptions{TopN: 10, RankDelta: 5})
	if len(d.ProviderDisplacements) != 1 {
		t.Fatalf("want exactly 1 displacement entry, got %+v", d.ProviderDisplacements)
	}
	pd := d.ProviderDisplacements[0]
	if pd.ClientsAdded != 0 || len(pd.MigratedFrom) != 1 || pd.MigratedFrom[0].Clients != 1 {
		t.Fatalf("scanner must not appear as a client: %+v", pd)
	}
}

func TestCompareCompatibilityWarnings(t *testing.T) {
	base := graph.Snapshot{Meta: graph.SnapshotMeta{
		ClusterName: "alpha",
		Window:      "24h",
		Scope:       []string{"10.0.0.0/24", "10.0.1.0/24"},
		Sensors:     []string{"sensor-a"},
	}}
	next := graph.Snapshot{Meta: graph.SnapshotMeta{
		ClusterName: "bravo",
		Window:      "168h",
		Scope:       []string{"10.0.2.0/24"},
		Sensors:     []string{"sensor-b", "sensor-a"},
	}}

	d := Compare(base, next, DiffOptions{TopN: 10, RankDelta: 5})
	if !reflect.DeepEqual(d.CompatibilityWarnings, []string{
		`cluster differs: "alpha" vs "bravo"`,
		`window differs: "24h" vs "168h"`,
		`scope differs: 10.0.0.0/24, 10.0.1.0/24 vs 10.0.2.0/24`,
		`sensors differ: sensor-a vs sensor-a, sensor-b`,
	}) {
		t.Fatalf("compatibility warnings = %#v", d.CompatibilityWarnings)
	}
}

func TestCompareIdentityChanges(t *testing.T) {
	base := graph.Snapshot{
		Nodes: []graph.Node{{
			IP:              "10.0.0.10",
			TLSFingerprints: []string{"fp-a"},
			SSHHostKeys:     []string{"ssh-a"},
		}},
	}
	next := graph.Snapshot{
		Nodes: []graph.Node{{
			IP:              "10.0.0.10",
			TLSFingerprints: []string{"fp-b"},
			SSHHostKeys:     []string{"ssh-a", "ssh-b"},
		}},
	}
	d := Compare(base, next, DiffOptions{TopN: 10, RankDelta: 5})
	if len(d.IdentityChanges) != 2 {
		t.Fatalf("identity changes = %#v", d.IdentityChanges)
	}
	if !reflect.DeepEqual(d.IdentityChanges[0], IdentityChange{
		IP:       "10.0.0.10",
		Protocol: "ssh",
		Added:    []string{"ssh-b"},
	}) {
		t.Fatalf("ssh change = %#v", d.IdentityChanges[0])
	}
	if !reflect.DeepEqual(d.IdentityChanges[1], IdentityChange{
		IP:       "10.0.0.10",
		Protocol: "tls",
		Added:    []string{"fp-b"},
		Removed:  []string{"fp-a"},
	}) {
		t.Fatalf("tls change = %#v", d.IdentityChanges[1])
	}
}
