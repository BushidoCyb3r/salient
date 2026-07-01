package snapshot

import (
	"os"
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	snap := graph.Snapshot{
		Meta: graph.SnapshotMeta{
			CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			Window:    "336h", ClusterName: "test", Tool: "defilade",
		},
		Nodes: []graph.Node{{IP: "10.0.1.10", Subnet: "10.0.1.0/24", Scores: graph.ScoreSet{Rank: 1, Composite: 0.9}}},
		Edges: []graph.Edge{{Src: "10.0.2.30", Dst: "10.0.1.10", Port: 88, Service: "kerberos", ConnCount: 100}},
	}
	path, err := Save(dir, snap)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("snapshot file mode = %v, want 0600", fi.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nodes[0].IP != "10.0.1.10" || got.Edges[0].Port != 88 || got.Meta.Window != "336h" {
		t.Errorf("round trip mismatch: %+v", got)
	}
	entries, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Nodes != 1 || entries[0].Edges != 1 {
		t.Errorf("bad index: %+v", entries)
	}
}
