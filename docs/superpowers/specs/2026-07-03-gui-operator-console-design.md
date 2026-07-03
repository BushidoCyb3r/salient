# GUI Operator Console Design

**Goal:** Turn the viewer-only Defilade desktop GUI into an operator console that
can connect to an Elasticsearch grid, run a scan from inside the window with live
feedback, and browse the resulting snapshots/maps — styled as a dark C2-style
console (AdaptixC2 feel).

**Explicit constraint override:** The original desktop-map-viewer spec made the GUI
"viewer only: no Elasticsearch calls, no triggering scan/diff/reconcile." The user
has deliberately overridden that: the GUI now holds ES credentials and runs scans.
The credential-at-rest risk is mitigated by keeping the API key in memory only
(never written to disk, never emitted in events/logs).

## Decisions (from brainstorming)

- **Theme:** whole app dark, not just the launch screen.
- **Scan form:** full scan config — ES URL, API key, CA cert path, insecure-skip-verify,
  window, scope CIDRs, timezone.
- **Credentials:** in-memory only; re-enter each launch; nothing persisted.
- **Landing:** unified console after connect — snapshot list + Run Scan + live task
  output + map in one dashboard.

## Architecture

### 1. Extract the scan pipeline into `internal/scan`

`runScan` in `cmd/defilade/scan.go` is `package main` and cannot be imported by the
`gui/` module. Extract the orchestration (currently ~100 lines) into a new
`internal/scan` package so the CLI and GUI share one tested implementation instead
of duplicating it.

```go
package scan

type Options struct {
	Window   time.Duration
	Scope    []string
	MaxEdges int
	TZ       string
}

// Stage is one progress step reported during a run.
type Stage struct {
	Name   string // machine-stable: "aggregating-edges", "scoring", "saving", ...
	Detail string // human line: "3,421 edges"
}

type Result struct {
	SnapshotPath string
	ReportPath   string
	MapPath      string
	Snapshot     graph.Snapshot
}

// Run executes fetch -> build -> score -> temporal -> infer -> save snapshot ->
// write report -> write map against an already-connected client, invoking
// report(Stage) at each step. Writes artifacts under dataDir (0600/0700).
func Run(ctx context.Context, cli *escli.Client, fm escli.FieldMap, info escli.ClusterInfo,
	opts Options, dataDir string, report func(Stage)) (Result, error)
```

`cmd/defilade/scan.go`'s `runScan` becomes a thin wrapper whose `report` prints the
same lines it prints today (edges aggregated, graph scored, snapshot/report/map
paths, top terrain). The CLI `scan` command's observable behavior — output text and
written files — is unchanged. `writeReport`/`writeBriefingMap` move into
`internal/scan` (they only wrap `report.HTML`/`report.HTMLMap` + file creation).

The truncation warning, empty-edges error, temporal second pass, sensor list,
gateway-candidate fallback, and zero-coverage computation all move with the pipeline.

### 2. Backend bound methods (`gui/app.go`)

`App` gains an in-memory client field and a scan cancel func:

```go
type App struct {
	ctx     context.Context
	DataDir string
	cli     *escli.Client      // set by Connect; nil until connected
	info    escli.ClusterInfo
	fm      escli.FieldMap
	cancel  context.CancelFunc // set while a scan runs
}
```

Methods:

- `Connect(req ConnectRequest) (escli.ClusterInfo, error)` — builds `escli.Config`
  from `{ESURL, APIKey, CACertPath, InsecureSkipVerify}`, `escli.New`, `cli.Info(ctx)`
  to validate auth, loads the field map, stores `cli`/`info`/`fm` on `App`. Returns
  cluster identity for the UI header. `ConnectRequest` carries the fieldmap path too
  (optional).
- `RunScan(req ScanRequest) error` — requires a prior `Connect`; parses
  `{Window, Scope, MaxEdges, TZ}`, creates a cancelable context stored in `App.cancel`,
  calls `scan.Run` with `report` = `runtime.EventsEmit(ctx, "scan:progress", stage)`.
  On success emits `scan:done` with the `Result` (snapshot path so the frontend loads
  the new map). On error emits `scan:error`.
- `CancelScan()` — calls `App.cancel` if a scan is running.

The API key is never placed in a `Stage`, event payload, or log line.

### 3. Frontend (dark console)

Two screens in the single Wails window:

**Launch / connect** — near-black background (`#0d1117`), the Defilade logo large and
centered, connection form beneath it: ES URL, API key (`type=password`), CA cert path,
insecure checkbox, window, scope CIDRs, timezone; a single **Connect** button. Teal/cyan
accent. Connect errors show inline (bad auth, unreachable grid).

**Console (after connect)** — one dashboard:
- Top bar: connected cluster name + health dot, **Run Scan** and **Cancel** buttons.
- Left sidebar: snapshot list (existing `ListSnapshots`), newest first.
- Center: the Cytoscape briefing map (existing port), restyled for a dark background
  (node/edge/group/tier colors adjusted; legend readable on dark).
- Task-output panel: streams `scan:progress` events as timestamped lines, C2 task-log
  style, with a live pulse while running; `scan:done` refreshes the list and loads the
  new snapshot's map; the terrain-handling reminder prints after each scan.

The logo (`defilade-logo.png` at repo root) is copied into `gui/frontend/public/` so
Vite ships it; referenced big and centered on the launch screen.

### 4. Security

- API key: password input, in-memory only, never persisted, never in events/logs.
- Artifacts stay `0600` in `0700` dirs (unchanged, handled in `snapshot.Save` and the
  report/map writers moving into `internal/scan`).
- Post-scan handling reminder surfaced in the console.
- `--insecure-skip-verify` equivalent is a checkbox; when on, the console shows the same
  TLS-disabled warning the CLI prints.

## Testing

- `internal/scan.Run` against the existing fake-ES `httptest` harness (as in
  `internal/escli/client_test.go`): asserts a snapshot is produced and stages fire in
  the expected order.
- `App.Connect` / `App.RunScan` unit-tested against a fake ES `httptest` server:
  Connect stores a usable client; RunScan produces a snapshot on disk and emits a
  terminal event. Wails runtime event emission is exercised only where a context is
  available; pure-logic paths are tested without the runtime.
- CLI regression: existing `cmd/defilade` tests must still pass unchanged after the
  pipeline extraction.

## Out of scope (this iteration)

- Running `diff`/`reconcile`/`analyze` from the GUI (scan only for now).
- Persisting connection profiles.
- Sensor-coverage map toggle (already deferred from the initial port).
