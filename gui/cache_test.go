package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/netconfig"
)

// TestLoadSnapshotCachesAndInvalidates proves the one-entry snapshot cache
// serves repeat loads without touching disk, and that invalidation forces a
// fresh read (which then fails because the file is gone).
func TestLoadSnapshotCachesAndInvalidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json.gz")
	writeSnapshot(t, path, graph.Snapshot{
		Meta: graph.SnapshotMeta{ClusterName: "cache-me"},
	})
	a := &App{DataDir: dir}
	resolved := a.resolveSnapshotPath(path)

	first, err := a.loadSnapshot(resolved)
	if err != nil || first.Meta.ClusterName != "cache-me" {
		t.Fatalf("first loadSnapshot = %#v, err=%v", first.Meta, err)
	}

	// Delete the file behind the cache's back: a cache hit must not re-read it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cached, err := a.loadSnapshot(resolved)
	if err != nil || cached.Meta.ClusterName != "cache-me" {
		t.Fatalf("cached loadSnapshot re-read disk: %#v, err=%v", cached.Meta, err)
	}

	// After invalidation the next read hits the (now-missing) file and errors.
	a.invalidateSnapshotCache()
	if _, err := a.loadSnapshot(resolved); err == nil {
		t.Fatal("loadSnapshot after invalidate: err = nil, want a read error")
	}
}

// TestDeclaredArtifactCacheInvalidatesOnClear proves the declared-config cache
// serves repeat reads without touching disk and that ClearDeclared invalidates
// it (so a subsequent read reflects the removed file).
func TestDeclaredArtifactCacheInvalidatesOnClear(t *testing.T) {
	dir := t.TempDir()
	a := &App{DataDir: dir}
	raw, err := json.Marshal(declaredArtifact{
		Devices: []netconfig.DeclaredDevice{{Hostname: "edge-rtr-01"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.declaredPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	art, err := a.loadDeclaredArtifact()
	if err != nil || art == nil || len(art.Devices) != 1 {
		t.Fatalf("first load = %#v, err=%v", art, err)
	}

	// Remove behind the cache's back: a cache hit must still return the device.
	if err := os.Remove(a.declaredPath()); err != nil {
		t.Fatal(err)
	}
	if art, err := a.loadDeclaredArtifact(); err != nil || art == nil {
		t.Fatalf("cached load re-read disk: art=%#v err=%v", art, err)
	}

	// ClearDeclared invalidates; the next read reflects the missing file.
	if err := a.ClearDeclared(); err != nil {
		t.Fatal(err)
	}
	if art, err := a.loadDeclaredArtifact(); err != nil || art != nil {
		t.Fatalf("load after ClearDeclared = %#v, err=%v, want nil", art, err)
	}
}
