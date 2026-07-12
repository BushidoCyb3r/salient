package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

func TestDriftHTMLRendersEverySignalAndHandlingBanner(t *testing.T) {
	d := snapshot.Diff{
		CompatibilityWarnings: []string{`cluster differs: "alpha" vs "bravo"`},
		AppearedNodes:         []graph.Node{{IP: "10.0.0.4"}},
		DisappearedNodes:      []graph.Node{{IP: "10.0.0.3"}},
		RankChanges:           []snapshot.RankChange{{IP: "10.0.0.1", FromRank: 1, ToRank: 7, Delta: -6}},
		NewEdgesToTop:         []graph.Edge{{Src: "10.0.0.4", Dst: "10.0.0.2", Port: 445, Evidence: graph.EvidenceProtocolConfirmed}},
		VanishedCriticalEdges: []graph.Edge{{Src: "10.0.0.2", Dst: "10.0.0.1", Port: 53}},
		RoleChanges:           []snapshot.RoleChange{{IP: "10.0.0.1", From: []graph.Role{graph.RoleDNS}, To: []graph.Role{graph.RoleDC}}},
		IdentityChanges:       []snapshot.IdentityChange{{IP: "10.0.0.10", Protocol: "tls", Added: []string{"fp-b"}, Removed: []string{"fp-a"}}},
		NewProviders:          []snapshot.NewProvider{{IP: "10.0.0.99", Port: 53, Service: "dns", Clients: 2, NewHost: true, Rank: 40}},
		ProviderDisplacements: []snapshot.ProviderDisplacement{{IP: "10.0.0.10", Port: 53, Service: "dns", ClientsAdded: 1, Rank: 5,
			MigratedFrom: []snapshot.MigrationSource{{IP: "10.0.0.20", Port: 53, Clients: 2}}}},
	}
	var out bytes.Buffer
	if err := DriftHTML(&out, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Handle at the classification", "Appeared nodes", "Disappeared nodes", "Rank changes",
		"New edges to critical nodes", "Vanished critical edges", "Role changes",
		"Identity changes", "10.0.0.10", "fp-b", "fp-a",
		"10.0.0.4", "10.0.0.3", "DNSServer", "DomainController",
		"New sensitive-service providers", "10.0.0.99", "dns", "protocol-confirmed",
		"Provider displacement", "10.0.0.10", "2 from 10.0.0.20:53",
		`Comparison warnings:`, `cluster differs: &#34;alpha&#34; vs &#34;bravo&#34;`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("HTML drift report missing %q", want)
		}
	}
}
