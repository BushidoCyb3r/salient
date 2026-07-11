// internal/hunt/leads_test.go
package hunt

import (
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/reconcile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

func baseSnapshot() graph.Snapshot {
	t0 := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	return graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Hostnames: []string{"dns1.corp"}, Subnet: "10.0.1.0/24",
				Roles: []graph.RoleAssertion{{Role: graph.RoleDNS}}, Scores: graph.ScoreSet{Rank: 3}},
			{IP: "10.0.1.99", Subnet: "10.0.1.0/24", Scores: graph.ScoreSet{Rank: 40}},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
			{IP: "10.0.3.31", Subnet: "10.0.3.0/24"},
			{IP: "10.0.4.40", Subnet: "10.0.4.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				Sensors: []string{"so-sensor-1"}, FirstSeen: t0, LastSeen: t0},
			{Src: "10.0.3.31", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				Sensors: []string{"so-sensor-1"}, FirstSeen: t0, LastSeen: t0},
			{Src: "10.0.4.40", Dst: "10.0.1.99", Port: 53, Evidence: graph.EvidenceProtocolConfirmed,
				Sensors: []string{"so-sensor-2"}, FirstSeen: t0, LastSeen: t0},
		},
	}
}

func TestBuildLeadsSoleProvider(t *testing.T) {
	// 10.0.1.11 is the only provider... except 10.0.1.99 also serves DNS in
	// baseSnapshot, so neither is "sole." Use a trimmed snapshot with exactly
	// one DNS provider to test the sole-provider reason in isolation.
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Subnet: "10.0.1.0/24", Scores: graph.ScoreSet{Rank: 3}},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	leads := BuildLeads(snap, nil, nil)
	if len(leads) != 1 || leads[0].Reason != ReasonSoleProvider || leads[0].IP != "10.0.1.11" {
		t.Fatalf("want 1 sole-provider lead, got %+v", leads)
	}
	if len(leads[0].Subnets) != 1 || leads[0].Subnets[0] != "10.0.3.0/24" {
		t.Errorf("bad subnets: %+v", leads[0].Subnets)
	}
}

func TestBuildLeadsNewProviderAndNewService(t *testing.T) {
	snap := baseSnapshot()
	diff := &snapshot.Diff{
		NewProviders: []snapshot.NewProvider{
			{IP: "10.0.1.99", Port: 53, Service: "dns", Clients: 1, NewHost: true, Rank: 40},
			{IP: "10.0.1.11", Port: 53, Service: "dns", Clients: 2, NewHost: false, Rank: 3},
		},
	}
	leads := BuildLeads(snap, diff, nil)
	byIP := map[string]Lead{}
	for _, l := range leads {
		byIP[l.IP] = l
	}
	if byIP["10.0.1.99"].Reason != ReasonNewProvider {
		t.Errorf("10.0.1.99 reason = %q, want new-provider", byIP["10.0.1.99"].Reason)
	}
	if byIP["10.0.1.11"].Reason != ReasonNewService {
		t.Errorf("10.0.1.11 reason = %q, want new-service", byIP["10.0.1.11"].Reason)
	}
}

func TestBuildLeadsUndocumentedAndContradicted(t *testing.T) {
	snap := baseSnapshot()
	rec := &reconcile.Result{
		ObservedUndocumented: []graph.Node{{IP: "10.0.1.99"}},
		RoleContradicted:     []reconcile.Contradiction{{IP: "10.0.1.11", Documented: "web server", Expected: graph.RoleWebServer, Observed: []graph.Role{graph.RoleDNS}}},
	}
	leads := BuildLeads(snap, nil, rec)
	byIP := map[string]Lead{}
	for _, l := range leads {
		byIP[l.IP] = l
	}
	if byIP["10.0.1.99"].Reason != ReasonUndocumented || byIP["10.0.1.99"].InventoryStatus != "undocumented" {
		t.Errorf("bad undocumented lead: %+v", byIP["10.0.1.99"])
	}
	if byIP["10.0.1.11"].Reason != ReasonContradicted || byIP["10.0.1.11"].InventoryStatus != "contradicted" {
		t.Errorf("bad contradicted lead: %+v", byIP["10.0.1.11"])
	}
}

func TestBuildLeadsDedupPrefersHigherPriorityReason(t *testing.T) {
	// A provider that is BOTH a new provider AND role-contradicted must appear
	// exactly once, with the higher-priority reason (contradicted), never twice.
	snap := baseSnapshot()
	diff := &snapshot.Diff{
		NewProviders: []snapshot.NewProvider{{IP: "10.0.1.11", Port: 53, Service: "dns", Clients: 2, NewHost: false, Rank: 3}},
	}
	rec := &reconcile.Result{
		RoleContradicted: []reconcile.Contradiction{{IP: "10.0.1.11", Documented: "web server", Expected: graph.RoleWebServer, Observed: []graph.Role{graph.RoleDNS}}},
	}
	leads := BuildLeads(snap, diff, rec)
	count := 0
	var found Lead
	for _, l := range leads {
		if l.IP == "10.0.1.11" && l.Port == 53 {
			count++
			found = l
		}
	}
	if count != 1 {
		t.Fatalf("want exactly 1 lead for 10.0.1.11:53, got %d", count)
	}
	if found.Reason != ReasonContradicted {
		t.Errorf("Reason = %q, want contradicted (higher priority than new-service)", found.Reason)
	}
}

func TestBuildLeadsSortOrder(t *testing.T) {
	// Contradicted must sort before sole-provider — reason priority is the
	// primary sort key, ahead of client count.
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Subnet: "10.0.1.0/24"},
			{IP: "10.0.1.20", Subnet: "10.0.1.0/24"},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
			{IP: "10.0.3.31", Subnet: "10.0.3.0/24"},
			{IP: "10.0.3.32", Subnet: "10.0.3.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.3.30", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceResponderConfirmed},
			{Src: "10.0.3.31", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceResponderConfirmed},
			{Src: "10.0.3.32", Dst: "10.0.1.20", Port: 445, Evidence: graph.EvidenceResponderConfirmed},
		},
	}
	rec := &reconcile.Result{
		RoleContradicted: []reconcile.Contradiction{{IP: "10.0.1.11", Documented: "web server", Expected: graph.RoleWebServer, Observed: []graph.Role{graph.RoleDNS}}},
	}
	leads := BuildLeads(snap, nil, rec)
	if len(leads) != 2 || leads[0].Reason != ReasonContradicted || leads[1].Reason != ReasonSoleProvider {
		t.Fatalf("want [contradicted, sole-provider] order, got %+v", leads)
	}
}
