# Desktop Map Viewer

A native window (Linux/macOS/Windows) for browsing saved Defilade
snapshots and their briefing maps — reuses the same Cytoscape map as
`defilade map --format html`, with added right-click actions and search.

It is a **viewer only**: it never talks to Elasticsearch and never
triggers a scan, diff, or reconcile. Run those with the CLI first;
the GUI reads whatever `<data-dir>/{snapshots,reports,maps}` already
has (default `defilade-data/`, same as the CLI).

## Building

Requires Go, Node.js/npm, and the Wails CLI
(`go install github.com/wailsapp/wails/v2/cmd/wails@latest`).

Linux additionally needs the system webview library:
- Debian/Ubuntu: `sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev`
- Fedora/RHEL/Rocky: `sudo dnf install webkit2gtk4.1-devel gtk3-devel`

```sh
make gui
```

(`make gui` adds the `webkit2_41` build tag automatically on Linux
distros that only ship webkit2gtk-4.1; a plain `cd gui && wails build`
works everywhere else.)

Produces a native binary/bundle under `gui/build/bin/`.

## Known gaps

- Builds are unsigned — expect a Gatekeeper warning on macOS and a
  SmartScreen warning on Windows on first launch.
- No cross-compilation: build on (or via CI for) each target OS.
- No sensor-coverage toggle yet (the CLI HTML map's `l-cov` layer) —
  dropped from the initial port.

## Manual QA checklist (per OS — no automated GUI test harness exists)

- [ ] App launches, native window opens (no browser chrome)
- [ ] Snapshot list populates from `<data-dir>`; entries whose
      `.json.gz` was deleted appear greyed out and unclickable
- [ ] Selecting a snapshot renders its map
- [ ] Right-click a node: Copy IP, Show evidence, Focus this group,
      Clear focus all work
- [ ] Search box dims non-matching nodes and clears on empty input
- [ ] File → Open Snapshot opens the native file picker
- [ ] File → Refresh re-scans the data directory
- [ ] Click-node evidence panel still works
