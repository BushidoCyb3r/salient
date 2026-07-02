package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

func TestMapCommandPrintsHandlingReminder(t *testing.T) {
	path := saveMapTestSnapshot(t)

	cmd := newMapCmd()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", filepath.Clean(path), "--format", "svg"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "Handling reminder") {
		t.Fatalf("stderr missing handling reminder: %q", stderr.String())
	}
}

func TestMapCommandHTMLPrintsHandlingReminder(t *testing.T) {
	cmd := newMapCmd()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", saveMapTestSnapshot(t), "--format", "html"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "Handling reminder") {
		t.Fatalf("stderr missing handling reminder: %q", stderr.String())
	}
}

func TestReportCommandPrintsHandlingReminder(t *testing.T) {
	cmd := newReportCmd()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", saveMapTestSnapshot(t), "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "Handling reminder") {
		t.Fatalf("stderr missing handling reminder: %q", stderr.String())
	}
}

func TestMapCommandRejectsInvalidFocus(t *testing.T) {
	cmd := newMapCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", saveMapTestSnapshot(t), "--focus", "not-a-cidr", "--format", "svg"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--focus") {
		t.Fatalf("expected --focus validation error, got %v", err)
	}
}

func TestMapCommandRejectsInvalidGroupPrefix(t *testing.T) {
	cmd := newMapCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", saveMapTestSnapshot(t), "--group-prefix", "33", "--format", "svg"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--group-prefix") {
		t.Fatalf("expected --group-prefix validation error, got %v", err)
	}
}

func TestMapCommandRejectsNegativeMinConns(t *testing.T) {
	cmd := newMapCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", saveMapTestSnapshot(t), "--min-conns", "-1", "--format", "svg"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--min-conns") {
		t.Fatalf("expected --min-conns validation error, got %v", err)
	}
}

func saveMapTestSnapshot(t *testing.T) string {
	t.Helper()
	path, err := snapshot.Save(t.TempDir(), graph.Snapshot{
		Meta:  graph.SnapshotMeta{CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)},
		Nodes: []graph.Node{{IP: "10.0.0.1", Subnet: "10.0.0.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}
