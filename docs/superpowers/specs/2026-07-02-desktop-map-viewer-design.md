# Desktop Map Viewer Design

## Goal

A native desktop app (Linux/macOS/Windows) that opens Defilade snapshots and
renders their briefing maps in a real window — no browser chrome, richer
graph interactions (right-click actions, search/filter) than the current
click-for-evidence panel. Replaces "open the HTML file in a browser" as the
primary way to look at a map, without touching how the map is produced.

## Decision: Wails (Go + native OS webview)

Considered three directions; picked Wails.

- **Wails (chosen):** Go backend, frontend renders in the OS's built-in
  webview (WebView2 / WKWebView / WebKitGTK) — a real native window, native
  menu bar, no bundled browser engine. Reuses the existing Cytoscape/fcose/
  dagre map almost unchanged; only the data-loading path changes (Go-bound
  method call instead of baked into the HTML at file-write time). Stays Go —
  no second language/toolchain. Smallest footprint of the three options: no
  bundled Chromium, no npm dependency tree, which matters for a tool built
  around an offline/air-gapped/minimal-attack-surface posture.
- **Electron (rejected):** Most mature desktop-app ecosystem, but drops Go
  entirely for the GUI layer, bundles its own Chromium (~100MB+), and pulls
  in an npm supply chain disproportionate to a passive recon tool's own
  stated values (§1 of DEFILADE_PLAN.md: offline, minimal, auditable).
- **Native widgets — Qt/Fyne (rejected):** Closest visually to a
  Qt-style app like AdaptixC2, but the entire interactive graph (compound
  subnet boxes, tiered layout, drift overlays, evidence panel) is HTML/JS —
  none of it is reusable against native canvas/widget APIs. Highest
  rebuild cost for a graph renderer that already works well.

Trade-off accepted: this needs cgo, so it can no longer cross-compile from
one Linux box the way `make cross` does today. It needs a build per target
OS (local machine or CI matrix). The existing CLI (`make build`, `make
cross`) is unaffected — it lives in a separate package the GUI never
imports, so it keeps building `CGO_ENABLED=0` exactly as before.

## Scope

**In scope (this spec):**
- View saved snapshots' briefing maps in a native window.
- Browse available snapshots/reports (replaces `defilade view`'s browser
  index with a native list).
- Right-click node actions (copy IP, show evidence, focus this group/dim
  the rest) and a search/filter box — the richer-interaction ask from the
  original request, now living in a native window instead of a browser tab.
- Buildable on Linux, macOS, and Windows.

**Out of scope (fast-follow, not this spec):**
- Talking to Elasticsearch. The GUI is a **viewer** for artifacts the CLI
  already produced (`scan`, `diff`, `reconcile` remain CLI-only). This keeps
  the read-only/offline boundary exactly where it already is.
- Triggering a scan, diff, or reconcile from inside the GUI.
- `--focus` / re-derivation controls inside the GUI (loads the map as
  already rendered by `mapview.Build`; regenerating a focused view still
  means re-running the CLI for now).
- Code signing / notarization. Unsigned builds will trigger Gatekeeper
  (macOS) and SmartScreen (Windows) warnings on first run — acceptable for
  now, called out as a known gap.

## Architecture

Single Go module (no new `go.mod`, no `go.work`) — cgo isolation comes from
package boundaries, not module boundaries: `go build ./cmd/defilade` never
imports the new GUI package, so it never pulls in cgo regardless of what
lives elsewhere in the same module.

```
gui/                    Wails project root
├── main.go             Wails app bootstrap, binds Go methods to frontend
├── backend.go           snapshot listing, model loading (reuses internal/snapshot, internal/mapview)
├── wails.json
└── frontend/
    ├── index.html       adapted from internal/report/maphtml.go's template
    └── app.js           existing map JS (cytoscape/fcose/dagre from web/) + new interactions
```

`gui/` imports `internal/snapshot`, `internal/mapview`, `internal/graph`
directly — same module, same import path, no duplication. The vendored JS
libraries in `web/` (`cytoscape.min.js`, `cytoscape-fcose.js`, etc.) are
reused as frontend assets rather than duplicated.

## Components

**1. Snapshot index (backend-bound method).** Refactor the directory-scan
logic `viewcmd.go`'s `writeBrowserIndex` already has (walk `<data-dir>/
{snapshots,reports,maps}`, group by timestamp) into a shared function
returning structured data, used by both the CLI's `view` command (unchanged
behavior) and the new GUI's snapshot list.

**2. Map viewer (frontend, Go-bound data).** The existing Cytoscape setup
from `maphtml.go` — compound subnet groups, tiered layout, fcose/dagre
toggle, layer toggles (heat/coverage/edge-labels/drift), click-node evidence
panel — ports over largely as-is. The one real change: `const model = {{.Model}}`
(baked into the HTML string at render time) becomes a call to a Wails-bound
Go method (e.g. `LoadModel(path string) (*mapview.Model, error)`) invoked
from JS after the user picks a snapshot.

**3. New interactions.**
- Right-click (`cxttap`) on a node opens a small floating menu: Copy IP,
  Show evidence (reuses the existing click-panel logic), Focus this group
  (dims every node outside the target's subnet via a new shared
  `dim`/`undim` helper).
- A search box in the sidebar: substring match against label/role/evidence,
  non-matches dim via the same helper, clears on empty input.
- Drag-to-move and box-select are already-on Cytoscape defaults — nothing to
  build, just true once the map is running in a window instead of an
  `<iframe>`-less static page (no change needed here, noted for completeness).

**4. Native shell.** Wails app menu: File → Open Snapshot (native file
picker, defaults to `<data-dir>/snapshots`), File → Refresh index. Window
title reflects the loaded snapshot's cluster name + timestamp.

## Data flow

1. App launches → calls `ListSnapshots()` → populates the sidebar list.
2. User selects a snapshot → calls `LoadModel(path)` → Go loads + decompresses
   the `.json.gz` and runs `mapview.Build` fresh, rather than reusing a
   previously-rendered `.map.html`'s embedded model. `mapview.Build` is
   already a pure function of the snapshot (its own doc comment says so) —
   re-deriving keeps one code path instead of two, and means the GUI never
   depends on a stale rendered artifact existing on disk → returns JSON to
   the frontend.
3. Frontend renders exactly as the current HTML map does, plus the new
   interactions.

## Build & distribution

- New Makefile target, e.g. `make gui`, wrapping `wails build` — runs
  against whatever OS it's invoked on (no cross-compile).
- CI: new matrix job (`ubuntu-latest`, `macos-latest`, `windows-latest`) in
  `.github/workflows/ci.yml` running `wails build`, uploading each as a
  build artifact. Does not touch the existing `test` job or `make cross`.
- Runtime dependency: WebKitGTK on Linux (present on most desktop distros,
  not guaranteed on minimal/server installs — call this out in the GUI's
  README/install docs).
- This dev box has no gcc yet (being installed) and no display — final
  visual QA on Linux happens once gcc lands; macOS/Windows visual QA needs
  to happen on those platforms directly (this box can't render or
  screenshot a GUI window at all).

## Error handling

- Missing/corrupt snapshot file: surface the existing `snapshot.Load` error
  in the UI (a dismissible banner), don't crash the app.
- No WebKitGTK / webview runtime found (Linux): Wails itself fails to start
  with a clear error; document the apt/dnf package name in the install docs.
- Empty `<data-dir>`: show an empty-state message with the expected path,
  same tone as the CLI's existing "no snapshots found" behavior.

## Testing

- Go: unit tests on the bound methods (`ListSnapshots`, `LoadModel`) using
  the same snapshot fixtures `internal/mapview`'s tests already build —
  table-driven, no Wails runtime needed (these are plain Go functions Wails
  exposes, testable in isolation).
- Frontend: no headless GUI test harness in this repo today; the JS
  additions get the same self-contained/smoke-style assertions the existing
  `TestHTMLMapSelfContainedAndHasEvidence` uses, adapted for the new
  frontend files (checks the new interaction code and markers are present).
- Manual QA checklist (per OS, since this box can't render a GUI): app
  launches, snapshot list populates, map renders, right-click menu works,
  search dims correctly, layout toggle still works, evidence panel still
  works.

## Risks / open questions

- Per-OS builds mean macOS and Windows artifacts can only be produced (and
  properly QA'd) by CI or by someone on that OS — this repo's dev loop has
  been single-box-Linux until now.
- Unsigned installers will warn on first launch on macOS/Windows (Gatekeeper/
  SmartScreen) until code signing is set up — explicitly deferred, not
  blocking.
