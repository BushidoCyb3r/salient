package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
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

func TestSuggestTagsPersistsSafeSidecarAndLoadModelOverlaysIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret-key" {
			t.Errorf("Authorization = %q", got)
		}
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"tags\":[{\"node_id\":\"10.0.0.10\",\"tags\":[\"web server\",\"public facing\"],\"confidence\":0.87,\"rationale\":\"Receives web traffic\"}]}"}}]}`)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "snapshot.json.gz")
	writeSnapshot(t, path, graph.Snapshot{
		Nodes: []graph.Node{{
			IP: "10.0.0.10", Subnet: "10.0.0.0/24",
			Roles: []graph.RoleAssertion{{Role: graph.RoleWebServer}},
		}},
	})
	a := &App{ctx: context.Background()}
	result, err := a.SuggestTags(TagRequest{
		SnapshotPath: path,
		Provider:     "openai",
		Endpoint:     server.URL,
		Model:        "test-model",
		APIKey:       "secret-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tags) != 1 || result.Tags[0].NodeID != "10.0.0.10" {
		t.Fatalf("SuggestTags() = %#v", result)
	}

	sidecar := path + ".tags.json"
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-key")) {
		t.Fatal("tag sidecar contains the API key")
	}
	var artifact TagArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Model != "test-model" || artifact.EndpointHost == "" || len(artifact.Tags) != 1 {
		t.Fatalf("tag sidecar = %#v", artifact)
	}
	if info, err := os.Stat(sidecar); err != nil {
		t.Fatal(err)
	} else if goruntime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("tag sidecar mode = %o, want 600", info.Mode().Perm())
	}

	model, err := a.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 1 || len(model.Nodes[0].SuggestedTags) != 2 || model.Nodes[0].SuggestionModel != "test-model" {
		t.Fatalf("LoadModel() tag overlay = %#v", model.Nodes)
	}
}

func TestSuggestTagsForHostsMergesSidecar(t *testing.T) {
	reply := func(nodeID, tag string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"choices":[{"message":{"content":"{\"tags\":[{\"node_id\":\"`+nodeID+`\",\"tags\":[\"`+tag+`\"],\"confidence\":0.8,\"rationale\":\"obs\"}]}"}}]}`)
		}
	}
	path := filepath.Join(t.TempDir(), "snapshot.json.gz")
	writeSnapshot(t, path, graph.Snapshot{Nodes: []graph.Node{
		{IP: "10.0.0.1", Subnet: "10.0.0.0/24"},
		{IP: "10.0.0.2", Subnet: "10.0.0.0/24"},
	}})
	a := &App{ctx: context.Background()}

	s1 := httptest.NewServer(reply("10.0.0.1", "camera"))
	defer s1.Close()
	if _, err := a.SuggestTagsForHosts(TagRequest{SnapshotPath: path, Provider: "openai", Endpoint: s1.URL, Model: "m"}, []string{"10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	s2 := httptest.NewServer(reply("10.0.0.2", "printer"))
	defer s2.Close()
	if _, err := a.SuggestTagsForHosts(TagRequest{SnapshotPath: path, Provider: "openai", Endpoint: s2.URL, Model: "m"}, []string{"10.0.0.2"}); err != nil {
		t.Fatal(err)
	}

	art, err := loadTagArtifact(path)
	if err != nil || art == nil {
		t.Fatalf("load artifact: %v %v", art, err)
	}
	got := map[string]bool{}
	for _, tg := range art.Tags {
		got[tg.NodeID] = true
	}
	if !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("disjoint targeted runs must both persist: %#v", art.Tags)
	}
}

func TestLoadFocusedModelDrillsIntoSegment(t *testing.T) {
	dataDir := t.TempDir()
	a := &App{DataDir: dataDir}
	path := filepath.Join(dataDir, "snapshot.json.gz")
	var nodes []graph.Node
	rank := 0
	add := func(ip, subnet string) {
		rank++
		nodes = append(nodes, graph.Node{IP: ip, Subnet: subnet,
			Scores: graph.ScoreSet{Composite: 1.0 - float64(rank)*0.001, Rank: rank}})
	}
	// Two VLANs, enough hosts to trigger overview at the top level.
	for v := 0; v < 40; v++ {
		add(fmt.Sprintf("10.1.1.%d", v+1), "10.1.1.0/24")
		add(fmt.Sprintf("10.2.2.%d", v+1), "10.2.2.0/24")
	}
	writeSnapshot(t, path, graph.Snapshot{Nodes: nodes})

	m, err := a.LoadFocusedModel(path, "10.1.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if m.Overview {
		t.Error("focused model must be full detail, not overview")
	}
	// Every host of the focused VLAN is present; the other VLAN is filtered out.
	shown, foreign := 0, 0
	for _, n := range m.Nodes {
		if strings.HasPrefix(n.ID, "10.1.1.") {
			shown++
		}
		if strings.HasPrefix(n.ID, "10.2.2.") {
			foreign++
		}
	}
	if shown != 40 {
		t.Errorf("focused VLAN shows %d hosts, want all 40", shown)
	}
	if foreign != 0 {
		t.Errorf("focused map leaked %d hosts from another VLAN", foreign)
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
		if goruntime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
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
	if goruntime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
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
