# Desktop Operator Console

A native window (Linux/macOS/Windows) that connects to a Security Onion grid,
runs scans with live progress, and browses the resulting snapshots and briefing
maps — reuses the same Cytoscape map as `defilade map --format html`, with added
right-click actions, search, and PNG/HTML/GraphML export.

It runs the same read-only scan pipeline as the CLI (`internal/scan`): the only
Elasticsearch traffic is the aggregation queries a `defilade scan` issues, and
the only writes are the snapshot, report, and map under `<data-dir>`
(default `defilade-data/`, same as the CLI). The API key lives in memory only —
never persisted to disk, never included in an emitted event. Model-assisted
`analyze`, `diff`, and `reconcile` stay CLI-only; the console reads whatever
snapshots those and its own scans leave in `<data-dir>/{snapshots,reports,maps}`.

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

## Running (runtime dependencies)

The built binary is dynamically linked against the system webview at run
time — the machine that *runs* it needs the runtime libraries (the `-devel`
packages above are only needed to *build*):

- Debian/Ubuntu: `sudo apt-get install libwebkit2gtk-4.1-0 libgtk-3-0`
- Fedora/RHEL/Rocky: `sudo dnf install webkit2gtk4.1 gtk3`

RHEL-family (Rocky/RHEL/Fedora) is a supported build and run target, not just
Debian/Ubuntu. On RHEL the webview ships as `webkit2gtk4.1`, so `make gui`
compiles with the `-tags webkit2_41` tag automatically (it probes
`pkg-config --exists webkit2gtk-4.1`).

## Known gaps

- Builds are unsigned — expect a Gatekeeper warning on macOS and a
  SmartScreen warning on Windows on first launch.
- No cross-compilation: build on (or via CI for) each target OS.
- No sensor-coverage toggle yet (the CLI HTML map's `l-cov` layer) —
  dropped from the initial port.

## Manual QA checklist (per OS — no automated GUI test harness exists)

Exercise against the fake grid: `go run ./testdata/fakees -port 9299`, connect to
`http://127.0.0.1:9299` with any base64 key (e.g. `dGVzdDp0ZXN0`).

- [ ] App launches, native window opens (no browser chrome)
- [ ] Launch screen shows the centered logo and connect form
- [ ] Cmd/Ctrl+V pastes into the connect-form inputs (native Edit menu)
- [ ] Connect succeeds; the cluster name from the grid renders as plain
      text (no markup injection), and the console swaps in
- [ ] A bad URL / unreachable host shows an inline connect error and
      re-enables the Connect button (does not spin forever)
- [ ] Run Scan streams timestamped progress lines; Cancel aborts a
      running scan; the handling reminder prints on completion
- [ ] A completed scan refreshes the snapshot list and loads the new map
- [ ] Snapshot list populates from `<data-dir>`; entries whose
      `.json.gz` was deleted appear greyed out and unclickable
- [ ] Selecting a snapshot renders its map (dark theme)
- [ ] Export PNG / HTML / GraphML each save via the native Save dialog;
      cancelling the dialog is a no-op (no error)
- [ ] Right-click a node: Copy IP, Show evidence, Focus this group,
      Clear focus all work
- [ ] Search box dims non-matching nodes and clears on empty input
- [ ] File → Open Snapshot opens the native file picker
- [ ] File → Refresh re-scans the data directory
- [ ] Click-node evidence panel still works
