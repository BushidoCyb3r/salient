package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func TestDefaultDataDirIsAbsoluteUnderHome(t *testing.T) {
	got := defaultDataDir()
	if !filepath.IsAbs(got) {
		t.Fatalf("defaultDataDir() = %q, want an absolute path", got)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, config.DataDirName)
	if got != want {
		t.Fatalf("defaultDataDir() = %q, want %q", got, want)
	}
}

func TestListSnapshotsFindsReportArtifact(t *testing.T) {
	dataDir := t.TempDir()
	reports := filepath.Join(dataDir, "reports")
	if err := os.Mkdir(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reports, "20260702T120000Z.html"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := (&App{DataDir: dataDir}).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Timestamp != "20260702T120000Z" {
		t.Fatalf("ListSnapshots() = %#v", got)
	}
}

func TestLoadModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json.gz")
	snap := graph.Snapshot{
		Meta: graph.SnapshotMeta{ClusterName: "test-cluster"},
		Nodes: []graph.Node{{
			IP: "10.0.0.10", Subnet: "10.0.0.0/24",
			Roles:  []graph.RoleAssertion{{Role: graph.RoleWebServer}},
			Scores: graph.ScoreSet{Composite: 1, Rank: 1},
		}},
	}
	writeSnapshot(t, path, snap)

	got, err := (&App{}).LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Meta.ClusterName != "test-cluster" || len(got.Nodes) != 1 {
		t.Fatalf("LoadModel() = %#v", got)
	}
}

func TestExportMapWritesEachFormat(t *testing.T) {
	snapPath := filepath.Join(t.TempDir(), "snapshot.json.gz")
	writeSnapshot(t, snapPath, graph.Snapshot{
		Meta:  graph.SnapshotMeta{ClusterName: "test-cluster"},
		Nodes: []graph.Node{{IP: "10.0.0.10", Subnet: "10.0.0.0/24"}},
	})

	for _, tc := range []struct {
		format, ext, marker string
	}{
		{"html", ".html", "<html"},
		{"graphml", ".graphml", "<graphml"},
	} {
		outDir := t.TempDir()
		a := &App{saveFileFn: func(opts runtime.SaveDialogOptions) (string, error) {
			if opts.DefaultFilename == "" {
				t.Fatal("SaveDialogOptions.DefaultFilename is empty")
			}
			return filepath.Join(outDir, "out"+tc.ext), nil
		}}
		saved, err := a.ExportMap(snapPath, tc.format)
		if err != nil {
			t.Fatalf("%s: %v", tc.format, err)
		}
		body, err := os.ReadFile(saved)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), tc.marker) {
			t.Errorf("%s export missing %q marker", tc.format, tc.marker)
		}
		info, err := os.Stat(saved)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s export mode = %o, want 600", tc.format, info.Mode().Perm())
		}
	}
}

func TestExportMapCancelledDialogReturnsNoError(t *testing.T) {
	snapPath := filepath.Join(t.TempDir(), "snapshot.json.gz")
	writeSnapshot(t, snapPath, graph.Snapshot{Meta: graph.SnapshotMeta{ClusterName: "x"}})
	a := &App{saveFileFn: func(runtime.SaveDialogOptions) (string, error) { return "", nil }}
	saved, err := a.ExportMap(snapPath, "html")
	if err != nil || saved != "" {
		t.Fatalf("ExportMap() = %q, %v; want empty path, nil error on cancel", saved, err)
	}
}

func TestExportMapUnknownFormat(t *testing.T) {
	snapPath := filepath.Join(t.TempDir(), "snapshot.json.gz")
	writeSnapshot(t, snapPath, graph.Snapshot{Meta: graph.SnapshotMeta{ClusterName: "x"}})
	if _, err := (&App{}).ExportMap(snapPath, "pdf"); err == nil {
		t.Fatal("ExportMap() with an unknown format should error")
	}
}

func TestExportImageWritesDecodedPNG(t *testing.T) {
	outDir := t.TempDir()
	a := &App{saveFileFn: func(opts runtime.SaveDialogOptions) (string, error) {
		if opts.DefaultFilename == "" {
			t.Fatal("SaveDialogOptions.DefaultFilename is empty")
		}
		return filepath.Join(outDir, "out.png"), nil
	}}
	png := []byte{0x89, 'P', 'N', 'G', 1, 2, 3}
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)

	saved, err := a.ExportImage(dataURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, png) {
		t.Fatalf("ExportImage() wrote %v, want %v", body, png)
	}
	info, err := os.Stat(saved)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("ExportImage() mode = %o, want 600", info.Mode().Perm())
	}
}

func TestExportImageCancelledDialogReturnsNoError(t *testing.T) {
	a := &App{saveFileFn: func(runtime.SaveDialogOptions) (string, error) { return "", nil }}
	png := []byte{1, 2, 3}
	saved, err := a.ExportImage("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	if err != nil || saved != "" {
		t.Fatalf("ExportImage() = %q, %v; want empty path, nil error on cancel", saved, err)
	}
}

func TestExportImageRejectsNonPNGDataURL(t *testing.T) {
	if _, err := (&App{}).ExportImage("data:text/plain;base64,aGVsbG8="); err == nil {
		t.Fatal("ExportImage() with a non-PNG data URL should error")
	}
}

func TestLoadModelMissingSnapshot(t *testing.T) {
	if _, err := (&App{}).LoadModel(filepath.Join(t.TempDir(), "missing.json.gz")); err == nil {
		t.Fatal("LoadModel() error = nil")
	}
}

func TestLegend(t *testing.T) {
	got := (&App{}).Legend()
	if len(got) != 7 {
		t.Fatalf("Legend() has %d items, want 7", len(got))
	}
	if got[0].Label != config.ClassLabel(config.ClassAuth) || got[0].Color == "" {
		t.Fatalf("Legend()[0] = %#v", got[0])
	}
	raw, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if keys["Label"] == nil || keys["Color"] == nil || keys["label"] != nil || keys["color"] != nil {
		t.Fatalf("LegendItem JSON keys = %v, want Label and Color", keys)
	}
}

func writeSnapshot(t *testing.T, path string, snap graph.Snapshot) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	t.Cleanup(func() {
		_ = gz.Close()
		_ = f.Close()
	})
	if err := json.NewEncoder(gz).Encode(snap); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
