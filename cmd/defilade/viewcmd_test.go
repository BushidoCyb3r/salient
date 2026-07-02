package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteBrowserIndex(t *testing.T) {
	dataDir := t.TempDir()
	for _, dir := range []string{"reports", "maps"} {
		if err := os.Mkdir(filepath.Join(dataDir, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"20260101T000000Z.html", "20260201T000000Z.html"} {
		if err := os.WriteFile(filepath.Join(dataDir, "reports", name), []byte("report"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataDir, "maps", "20260201T000000Z.html"), []byte("map"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "index.html"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	path, err := writeBrowserIndex(dataDir, []byte("png"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if !strings.Contains(html, "data:image/png;base64,cG5n") {
		t.Fatal("index does not embed the logo")
	}
	if strings.Index(html, "20260201T000000Z") > strings.Index(html, "20260101T000000Z") {
		t.Fatal("index is not newest first")
	}
	if !strings.Contains(html, `href="reports/20260201T000000Z.html"`) || !strings.Contains(html, `href="maps/20260201T000000Z.html"`) {
		t.Fatal("index does not link the report and map")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("index mode = %o, want 600", got)
	}
}

func TestBrowserCommandLinuxUsesGIO(t *testing.T) {
	lookPath := func(name string) (string, error) {
		if name == "gio" {
			return "/usr/bin/gio", nil
		}
		return "", errors.New("not found")
	}
	name, args, err := browserCommand("linux", "", "file:///tmp/index.html", lookPath)
	if err != nil {
		t.Fatal(err)
	}
	if name != "/usr/bin/gio" || strings.Join(args, " ") != "open file:///tmp/index.html" {
		t.Fatalf("command = %q %q", name, args)
	}
}

func TestBrowserCommandReportsMissingLauncher(t *testing.T) {
	_, _, err := browserCommand("linux", "", "file:///tmp/index.html", func(string) (string, error) {
		return "", errors.New("not found")
	})
	if err == nil {
		t.Fatal("expected missing-launcher error")
	}
}
