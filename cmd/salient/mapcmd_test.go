package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
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

func TestMapAndReportOutputsAreProtected(t *testing.T) {
	snapshotPath := saveMapTestSnapshot(t)
	for _, tc := range []struct {
		name   string
		cmd    *cobra.Command
		format string
	}{
		{"map", newMapCmd(), "svg"},
		{"report", newReportCmd(), "json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), tc.name+"."+tc.format)
			tc.cmd.SetOut(&bytes.Buffer{})
			tc.cmd.SetErr(&bytes.Buffer{})
			tc.cmd.SetArgs([]string{"--snapshot", snapshotPath, "--format", tc.format, "--output", output})
			if err := tc.cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(output)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("output mode = %o, want 600", info.Mode().Perm())
			}
		})
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

func TestMapCommandAcceptsFocusKeywords(t *testing.T) {
	for _, kw := range []string{"private", "public"} {
		cmd := newMapCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--snapshot", saveMapTestSnapshot(t), "--focus", kw, "--format", "svg"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("--focus %s should be accepted, got %v", kw, err)
		}
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
