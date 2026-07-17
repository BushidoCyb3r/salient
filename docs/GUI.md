# Desktop Operator Console

A native window (Linux/macOS/Windows) that connects to a Security Onion grid,
runs scans with live progress, and browses the resulting snapshots and briefing
maps — reuses the same Cytoscape map as `salient map --format html`, with added
right-click actions, search, and PNG/HTML/GraphML export.

It runs the same read-only scan pipeline as the CLI (`internal/scan`). Grid
traffic is limited to cluster information, index/field discovery, privilege
checks, and aggregate search queries. Scans write their snapshot, report, and
map under `<data-dir>` (default `salient-data/`, same as the CLI); operator
devices, sanitized declared configs, tag sidecars, and explicit exports are
also local-only. The API key lives in memory — never persisted to disk or
included in an emitted event. Model-assisted device tagging can submit a capped
snapshot summary to an operator-configured model endpoint and stores validated
suggestions in a separate protected sidecar. The console also loads drift
comparisons, asset reconciliation, and declared-config overlays through the
same backend packages as the CLI.

## Installing a release

Download the desktop build for your platform from
[GitHub Releases](https://github.com/BushidoCyb3r/salient/releases/latest):

- Debian/Ubuntu: the `.deb` asset
- Fedora/RHEL/Rocky: the `.rpm` asset
- macOS: `Salient-macOS.zip`
- Windows: `Salient-Windows.exe`

The Linux packages install the console as `salient-gui` and add a desktop-menu
entry. The macOS and Windows builds are unsigned, so verify the file against the
release's `SHA256SUMS` before accepting the platform warning. Assets labeled or
named `salient-cli-*` are the separate command-line binary.

## Building

Requires Go 1.26.5 or newer, Node.js/npm, and the platform packages below.
The repository installs its pinned Wails CLI version and all Go/npm dependencies:

Linux additionally needs the system webview library:
- Debian/Ubuntu: `sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev`
- Fedora/RHEL/Rocky: `sudo dnf install webkit2gtk4.1-devel gtk3-devel`

```sh
make gui-deps
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

- Release assets include `SHA256SUMS` and repository-hosted build provenance.
  Native platform signing is intentionally out of scope because it requires
  paid Apple and Microsoft signing credentials. Expect a Gatekeeper warning on
  macOS and a SmartScreen warning on Windows; verify checksums instead.
- No cross-compilation: build on (or via CI for) each target OS.
- No sensor-coverage toggle yet (the CLI HTML map's `l-cov` layer) —
  dropped from the initial port.

## Manual QA checklist

CI tests the Go backend, frontend helper modules, production frontend build, and
a headless-browser ready-state smoke path. Native window, webview, clipboard,
and file-dialog behavior still require this checklist on each target OS.

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
- [ ] AI Device Tagging stays disabled until a snapshot is selected
- [ ] Provider changes update endpoint/model defaults but both remain editable
- [ ] Loopback tagging works without egress consent; remote tagging fails until
      consent is checked and then requires HTTPS
- [ ] Successful tags visibly outline matching nodes and appear only under
      MODEL SUGGESTION in the evidence panel
- [ ] Restarting the console reloads suggestions from the `.tags.json` sidecar;
      the sidecar contains no API key
- [ ] Node evidence shows MAC and vendor when present; a UniFi/Cisco/etc. host
      shows a NetworkGear role and its vendor
- [ ] Aggregate "N other hosts" list shows MAC/vendor and filters by them;
      right-click a row for Assign to device / Set role / Pin to map
- [ ] **Suggest tags for listed hosts** tags only the filtered aggregate rows
      (≤100) and merges into the sidecar without clobbering other groups' tags
- [ ] Right-click a host → Pin to map: it renders as its own amber-bordered
      node; Unpin returns it to the aggregate; the pin survives a reload
- [ ] **show every private host (dense)** promotes RFC1918 hosts to their own
      nodes (external still collapses) and the choice persists across reloads
