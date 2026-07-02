package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

func TestDiffCommandWritesJSONAndHandlingReminder(t *testing.T) {
	from := saveDiffSnapshot(t, time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC), []graph.Node{{IP: "10.0.0.1", Scores: graph.ScoreSet{Rank: 1}}})
	to := saveDiffSnapshot(t, time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC), []graph.Node{{IP: "10.0.0.2", Scores: graph.ScoreSet{Rank: 1}}})

	cmd := newDiffCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--from", from, "--to", to, "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got snapshot.Diff
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if len(got.AppearedNodes) != 1 || len(got.DisappearedNodes) != 1 {
		t.Fatalf("unexpected diff: %+v", got)
	}
	if !strings.Contains(stderr.String(), "Handling reminder") {
		t.Fatalf("stderr missing handling reminder: %q", stderr.String())
	}
}

func TestDiffCommandWritesProtectedHTML(t *testing.T) {
	from := saveDiffSnapshot(t, time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC), nil)
	to := saveDiffSnapshot(t, time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC), []graph.Node{{IP: "10.0.0.2"}})
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--from", from, "--to", to, "--format", "html"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimSpace(stdout.String())
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("HTML mode = %o, want 600", info.Mode().Perm())
	}
}

func TestDiffCommandWritesDriftMap(t *testing.T) {
	from := saveDiffSnapshot(t, time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC), []graph.Node{
		{IP: "10.0.0.1", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 1}},
		{IP: "10.0.0.3", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 2}},
	})
	to := saveDiffSnapshot(t, time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC), []graph.Node{
		{IP: "10.0.0.1", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 7}},
		{IP: "10.0.0.4", Subnet: "10.0.0.0/24", Scores: graph.ScoreSet{Rank: 1}},
	})
	cmd := newDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--from", from, "--to", to, "--format", "html", "--map"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	paths := strings.Fields(stdout.String())
	if len(paths) != 2 {
		t.Fatalf("output paths = %q", stdout.String())
	}
	body, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("drift map mode = %o, want 600", info.Mode().Perm())
	}
	for _, want := range []string{`"drift":"new"`, `"drift":"vanished"`, `"drift":"rank-down"`} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("drift map missing %s", want)
		}
	}
}

func saveDiffSnapshot(t *testing.T, created time.Time, nodes []graph.Node) string {
	t.Helper()
	path, err := snapshot.Save(t.TempDir(), graph.Snapshot{Meta: graph.SnapshotMeta{CreatedAt: created}, Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	return path
}
