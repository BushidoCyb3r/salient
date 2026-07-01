package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/graph"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixture is a small fixed snapshot; CreatedAt pinned for determinism.
func fixture() graph.Snapshot {
	return graph.Snapshot{
		Meta: graph.SnapshotMeta{
			CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			Window:    "336h0m0s", ClusterName: "golden", Tool: "defilade",
			Sensors: []string{"sensor1"}, ZeroCovCIDRs: []string{"10.9.0.0/24"},
		},
		Nodes: []graph.Node{
			{IP: "10.0.1.10", Subnet: "10.0.1.0/24", Roles: []graph.RoleAssertion{
				{Role: graph.RoleDC, Confidence: 0.8, Evidence: []string{"20 distinct hosts made Kerberos requests to this host; LDAP also observed"}},
			}, Scores: graph.ScoreSet{Rank: 1, Composite: 0.91, DependencyInDegree: 20, PageRank: 0.3, Betweenness: 12}},
			{IP: "10.0.2.30", Subnet: "10.0.2.0/24", Roles: []graph.RoleAssertion{{Role: graph.RoleUnknown}},
				Scores: graph.ScoreSet{Rank: 2, Composite: 0.05}},
		},
		Edges: []graph.Edge{
			{Src: "10.0.2.30", Dst: "10.0.1.10", Port: 88, Service: "kerberos", ConnCount: 500,
				FirstSeen: time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC),
				LastSeen:  time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
		},
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run with -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file (run with -update after intentional changes)", name)
	}
}

func TestGraphMLGolden(t *testing.T) {
	var b bytes.Buffer
	if err := GraphML(&b, fixture()); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.graphml", b.Bytes())
}

func TestJSONGolden(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, fixture()); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.json", b.Bytes())
}

func TestHTMLRendersEvidenceAndBlindSpots(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, fixture()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"10.0.1.10", "DomainController", "Kerberos requests",
		"10.9.0.0/24",                  // blind-spot CIDR surfaced
		"Handle at the classification", // handling banner
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	if strings.Contains(out, "http://") || strings.Contains(out, "https://") {
		t.Error("HTML report references an external URL — must be fully self-contained")
	}
}
