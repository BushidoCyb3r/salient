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
	leads := BuildLeads(snap, nil, nil, nil)
	if len(leads) != 1 || leads[0].Reason != ReasonSoleProvider || leads[0].IP != "10.0.1.11" {
		t.Fatalf("want 1 sole-provider lead, got %+v", leads)
	}
	if len(leads[0].Subnets) != 1 || leads[0].Subnets[0] != "10.0.3.0/24" {
		t.Errorf("bad subnets: %+v", leads[0].Subnets)
	}
}

func TestBuildLeadsSuppressesApprovedProvider(t *testing.T) {
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Subnet: "10.0.1.0/24", Scores: graph.ScoreSet{Rank: 3}},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	approved := map[string]bool{ProviderKey("10.0.1.11", 53): true}
	leads := BuildLeads(snap, nil, nil, approved)
	if len(leads) != 0 {
		t.Fatalf("approved provider must be suppressed entirely, got %+v", leads)
	}
	// Guard the guard: an unrelated approval must not suppress this lead.
	leads = BuildLeads(snap, nil, nil, map[string]bool{ProviderKey("10.0.1.99", 445): true})
	if len(leads) != 1 {
		t.Fatalf("unrelated approval must not suppress this lead, got %+v", leads)
	}
}

func TestBuildLeadsAlternateProvidersOverlap(t *testing.T) {
	// Two DNS providers sharing one client (10.0.3.30 uses both) must list
	// each other as alternates. Neither is a "sole provider" (there are two),
	// so mark 10.0.1.11 undocumented via reconcile to give it a lead to
	// attach the AlternateProviders evidence to — AlternateProviders is
	// supplementary evidence on an existing lead, not a lead reason itself.
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Subnet: "10.0.1.0/24"},
			{IP: "10.0.1.12", Subnet: "10.0.1.0/24"},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
			{IP: "10.0.3.31", Subnet: "10.0.3.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.3.31", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.3.30", Dst: "10.0.1.12", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
		},
	}
	rec := &reconcile.Result{
		ObservedUndocumented: []graph.Node{{IP: "10.0.1.11"}, {IP: "10.0.1.12"}},
	}
	leads := BuildLeads(snap, nil, rec, nil)
	byIP := map[string]Lead{}
	for _, l := range leads {
		byIP[l.IP] = l
	}
	if got := byIP["10.0.1.11"].AlternateProviders; len(got) != 1 || got[0] != ProviderKey("10.0.1.12", 53) {
		t.Errorf("10.0.1.11 alternates = %+v, want [%s]", got, ProviderKey("10.0.1.12", 53))
	}
	if got := byIP["10.0.1.12"].AlternateProviders; len(got) != 1 || got[0] != ProviderKey("10.0.1.11", 53) {
		t.Errorf("10.0.1.12 alternates = %+v, want [%s]", got, ProviderKey("10.0.1.11", 53))
	}
}

func TestBuildLeadsNoAlternateProviderWhenClientsDisjoint(t *testing.T) {
	// baseSnapshot's two DNS providers (10.0.1.11 clients .30/.31,
	// 10.0.1.99 client .40) share no clients — neither should list the
	// other as an alternate. Force both into the lead list via reconcile
	// (neither is a "sole provider," so without this the assertion below
	// would silently check zero leads and pass vacuously).
	rec := &reconcile.Result{
		ObservedUndocumented: []graph.Node{{IP: "10.0.1.11"}, {IP: "10.0.1.99"}},
	}
	leads := BuildLeads(baseSnapshot(), nil, rec, nil)
	var dnsLeadsChecked int
	for _, l := range leads {
		if l.Service != "dns" {
			continue
		}
		dnsLeadsChecked++
		if len(l.AlternateProviders) != 0 {
			t.Errorf("%s: want no alternate providers (disjoint client sets), got %+v", l.IP, l.AlternateProviders)
		}
	}
	if dnsLeadsChecked != 2 {
		t.Fatalf("want 2 dns leads checked, got %d (leads: %+v)", dnsLeadsChecked, leads)
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
	leads := BuildLeads(snap, diff, nil, nil)
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
	leads := BuildLeads(snap, nil, rec, nil)
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
	leads := BuildLeads(snap, diff, rec, nil)
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

func TestBuildLeadsExcludesPortOnlyEdgesFromEnrichment(t *testing.T) {
	// A confirmed provider with one real client plus a port-only scanner probe
	// from an unrelated subnet: the scanner must not appear in SampleClients
	// or Subnets, since it never confirmed the service.
	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.1.11", Subnet: "10.0.1.0/24", Scores: graph.ScoreSet{Rank: 3}},
			{IP: "10.0.3.30", Subnet: "10.0.3.0/24"},
			{IP: "10.0.9.90", Subnet: "10.0.9.0/24"},
		},
		Edges: []graph.Edge{
			{Src: "10.0.3.30", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidenceProtocolConfirmed},
			{Src: "10.0.9.90", Dst: "10.0.1.11", Port: 53, Evidence: graph.EvidencePortOnly},
		},
	}
	leads := BuildLeads(snap, nil, nil, nil)
	if len(leads) != 1 || leads[0].IP != "10.0.1.11" {
		t.Fatalf("want 1 lead for 10.0.1.11, got %+v", leads)
	}
	lead := leads[0]
	for _, c := range lead.SampleClients {
		if c == "10.0.9.90" {
			t.Errorf("SampleClients contains port-only scanner: %+v", lead.SampleClients)
		}
	}
	for _, s := range lead.Subnets {
		if s == "10.0.9.0/24" {
			t.Errorf("Subnets contains port-only scanner's subnet: %+v", lead.Subnets)
		}
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
	leads := BuildLeads(snap, nil, rec, nil)
	if len(leads) != 2 || leads[0].Reason != ReasonContradicted || leads[1].Reason != ReasonSoleProvider {
		t.Fatalf("want [contradicted, sole-provider] order, got %+v", leads)
	}
}
