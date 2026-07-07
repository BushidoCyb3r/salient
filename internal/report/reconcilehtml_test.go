package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/reconcile"
)

func TestReconcileHTMLRendersAllSections(t *testing.T) {
	res := reconcile.Result{
		DocumentedSilent: []reconcile.SilentAsset{
			{Asset: reconcile.Asset{IP: "10.0.9.7", Hostname: "scada1", Role: "database", Segment: "SCADA"}, InBlindSpot: true},
			{Asset: reconcile.Asset{IP: "10.0.3.1", Hostname: "old-nas"}},
		},
		ObservedUndocumented: []graph.Node{
			{IP: "10.0.2.9", Hostnames: []string{"rogue"}, Roles: []graph.RoleAssertion{{Role: graph.RoleWebServer}}, Scores: graph.ScoreSet{Rank: 3}},
		},
		RoleContradicted: []reconcile.Contradiction{
			{IP: "10.0.1.5", Hostname: "dc01", Documented: "File Server", Expected: graph.RoleFileServer, Observed: []graph.Role{graph.RoleDC}},
		},
		Warnings: []string{"row 4: duplicate IP 10.0.1.5 — first occurrence kept"},
	}
	var b bytes.Buffer
	if err := ReconcileHTML(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"blind spot?", "scada1", "old-nas",
		"rogue", "WebServer", "#3",
		"dc01", "File Server", "DomainController",
		"duplicate IP",
		"Handle at the classification",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reconcile HTML missing %q", want)
		}
	}
}

func TestReconcileHTMLEmptyLists(t *testing.T) {
	var b bytes.Buffer
	if err := ReconcileHTML(&b, reconcile.Result{}); err != nil {
		t.Fatal(err)
	}
	if c := strings.Count(b.String(), "None —"); c != 3 {
		t.Errorf("empty-state count = %d, want 3", c)
	}
}
