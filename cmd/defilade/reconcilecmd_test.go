package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/reconcile"
)

func TestReconcileCommandJSON(t *testing.T) {
	snap := saveDiffSnapshot(t, time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC), []graph.Node{
		{IP: "10.0.1.5", Subnet: "10.0.1.0/24", Roles: []graph.RoleAssertion{{Role: graph.RoleDC}}},
		{IP: "10.0.2.9", Subnet: "10.0.2.0/24"},
	})
	assets := writeAssets(t, "ip,hostname,role\n10.0.1.5,dc01,file server\n10.0.3.1,old-nas,\nbadrow,,\n")

	cmd := newReconcileCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--snapshot", snap, "--assets", assets, "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got reconcile.Result
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if len(got.DocumentedSilent) != 1 || got.DocumentedSilent[0].IP != "10.0.3.1" {
		t.Errorf("silent = %+v", got.DocumentedSilent)
	}
	if len(got.ObservedUndocumented) != 1 || got.ObservedUndocumented[0].IP != "10.0.2.9" {
		t.Errorf("undocumented = %+v", got.ObservedUndocumented)
	}
	if len(got.RoleContradicted) != 1 || got.RoleContradicted[0].IP != "10.0.1.5" {
		t.Errorf("contradicted = %+v", got.RoleContradicted)
	}
	if len(got.Warnings) == 0 {
		t.Error("CSV warnings missing from result")
	}
	if !strings.Contains(stderr.String(), "Handling reminder") {
		t.Errorf("stderr missing handling reminder: %q", stderr.String())
	}
}

func TestReconcileCommandWritesProtectedHTMLAndMap(t *testing.T) {
	snap := saveDiffSnapshot(t, time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC), []graph.Node{
		{IP: "10.0.1.5", Subnet: "10.0.1.0/24"},
		{IP: "10.0.1.6", Subnet: "10.0.1.0/24"},
	})
	assets := writeAssets(t, "ip,vlan\n10.0.1.5,Server VLAN\n")

	cmd := newReconcileCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--snapshot", snap, "--assets", assets, "--format", "html", "--map"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	paths := strings.Fields(stdout.String())
	if len(paths) != 2 {
		t.Fatalf("output paths = %q", stdout.String())
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", p, info.Mode().Perm())
		}
	}
	body, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"drift":"undocumented"`, `Server VLAN`} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("reconcile map missing %s", want)
		}
	}
}

func TestReconcileCommandMapRequiresHTML(t *testing.T) {
	cmd := newReconcileCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--snapshot", "x", "--assets", "y", "--format", "json", "--map"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error: --map with --format json")
	}
}

func writeAssets(t *testing.T, csv string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "assets.csv")
	if err := os.WriteFile(p, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
