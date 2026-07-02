package snapshot

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanArtifacts(t *testing.T) {
	dataDir := t.TempDir()
	for _, dir := range []string{"reports", "maps", "snapshots"} {
		if err := os.Mkdir(filepath.Join(dataDir, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		"reports/20260101T000000Z.html",
		"reports/20260301T000000Z.html",
		"maps/20260201T000000Z.html",
		"snapshots/20260301T000000Z.json.gz",
		"snapshots/20260301T000000Z.json.gz.map.html",
		"snapshots/index.json",
	} {
		if err := os.WriteFile(filepath.Join(dataDir, filepath.FromSlash(name)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ScanArtifacts(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	want := []ArtifactEntry{
		{Timestamp: "20260301T000000Z", Report: "reports/20260301T000000Z.html", Snapshot: "snapshots/20260301T000000Z.json.gz"},
		{Timestamp: "20260201T000000Z", Map: "maps/20260201T000000Z.html"},
		{Timestamp: "20260101T000000Z", Report: "reports/20260101T000000Z.html"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanArtifacts() = %#v, want %#v", got, want)
	}
}

func TestScanArtifactsMissingDataDir(t *testing.T) {
	got, err := ScanArtifacts(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("ScanArtifacts() = %#v, want empty", got)
	}
}
