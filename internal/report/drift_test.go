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
		AppearedNodes:         []graph.Node{{IP: "10.0.0.4"}},
		DisappearedNodes:      []graph.Node{{IP: "10.0.0.3"}},
		RankChanges:           []snapshot.RankChange{{IP: "10.0.0.1", FromRank: 1, ToRank: 7, Delta: -6}},
		NewEdgesToTop:         []graph.Edge{{Src: "10.0.0.4", Dst: "10.0.0.2", Port: 445}},
		VanishedCriticalEdges: []graph.Edge{{Src: "10.0.0.2", Dst: "10.0.0.1", Port: 53}},
		RoleChanges:           []snapshot.RoleChange{{IP: "10.0.0.1", From: []graph.Role{graph.RoleDNS}, To: []graph.Role{graph.RoleDC}}},
	}
	var out bytes.Buffer
	if err := DriftHTML(&out, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Handle at the classification", "Appeared nodes", "Disappeared nodes", "Rank changes",
		"New edges to critical nodes", "Vanished critical edges", "Role changes",
		"10.0.0.4", "10.0.0.3", "DNSServer", "DomainController",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("HTML drift report missing %q", want)
		}
	}
}
