# GUI Operator Console — build handoff (2026-07-03)

Handoff so Codex (or a fresh session) can continue the desktop GUI work. Branch:
**`feature/desktop-map-viewer`** (NOT master). Do all GUI work there.

## Identity rule (hard)

Commit as `BushidoCyb3r <BushidoCyb3r@users.noreply.github.com>`. **Never** add a
`Co-Authored-By: Claude` / AI-vendor trailer or "Generated with" line — the user
deleted the whole GitHub repo once over exactly that, and history had to be
rewritten. No AI attribution in commits or PR bodies, ever.

## What the user asked for

Turn the viewer-only GUI into an operator console that *runs scans*, styled like
AdaptixC2 (dark C2 console). Decisions locked in brainstorming:

- **Whole app dark** (not just launch screen).
- **Full scan config** form: ES URL, API key, CA cert path, insecure-skip-verify,
  window, scope CIDRs, timezone.
- **API key in-memory only** — never persisted to disk, never in events/logs.
- **Unified console** after connect: snapshot list + Run Scan + live task output +
  map in one dashboard.
- Big **centered Defilade logo** on the launch/connect screen.
- **Live feedback** while a scan runs (C2 task-log feel).
- Must **build and run on RHEL-based Linux** (Rocky/RHEL/Fedora), not just
  Debian/Ubuntu. See "RHEL" below.

Full spec: `docs/superpowers/specs/2026-07-03-gui-operator-console-design.md`.

## Done (committed on feature/desktop-map-viewer)

1. `refactor: extract scan pipeline into internal/scan` (`41adf62`) — new
   `internal/scan` package with `Run(ctx, cli, fm, info, Options, dataDir, report func(Stage)) (Result, error)`.
   The whole fetch→build→score→temporal→infer→save→report→map pipeline plus the
   report/map writers moved out of `cmd/defilade/scan.go` (was `package main`,
   unreachable from the `gui/` module). CLI `scan` is now a thin wrapper; its
   output is equivalent (each stage prints its line, warnings to stderr).
   Tested: `internal/scan/scan_test.go` (fake-ES httptest, asserts snapshot +
   ordered stages + no-edges error).
2. `feat(gui): Connect/RunScan/CancelScan backend` (`bda1c60`) — `gui/app.go`:
   - `App` now holds an in-memory `*escli.Client`, `info`, `fm`, a `sync.Mutex`,
     and a `cancel context.CancelFunc`. Plus an `emitFn` test hook so the scan
     path is unit-testable without the Wails runtime.
   - `Connect(ConnectRequest) (escli.ClusterInfo, error)` — validates auth (GET /),
     resolves field map, stores client in memory.
   - `RunScan(ScanRequest) (*scan.Result, error)` — runs the pipeline, emits
     `scan:progress` per stage, then `scan:done` (snapshot path) or `scan:error`.
     Blocks until done; single-scan guard; API key never emitted.
   - `CancelScan()` — cancels the running scan's context.
   - Wails JS bindings regenerated (`make gui` did it): Connect, RunScan,
     CancelScan, plus existing ListSnapshots/LoadModel/Legend.
   - Tested: `gui/scan_test.go` (Connect stores client, RunScan emits
     progress+done and clears cancel, bad-window + not-connected errors).

## Frontend DONE (`d7dd7c9`)

Both screens built in one pass — `gui/frontend/index.html` + `gui/frontend/src/main.js`
are now the dark operator console: launch screen (centered logo + full connect form,
API key password field, inline errors) → console (top bar cluster + Run Scan/Cancel,
snapshot sidebar, dark-restyled Cytoscape map, streaming task-output panel wired to
scan:progress/done/error with a live pulse). Logo copied to `gui/frontend/public/`.
`gui/frontend_test.go` markers updated. `make gui` builds; gui + root tests pass.

## Remaining

- **Manual visual QA** on a machine with a display (headless box can't verify
  rendering/interaction): connect against the fake grid
  (`go run ./testdata/fakees -port 9299`, connect to `http://127.0.0.1:9299`, key
  `dGVzdDp0ZXN0`), run a scan, watch the task log stream, confirm the map renders
  dark and the new snapshot loads. Checklist scaffold in `docs/GUI.md`.
- **RHEL-family CI job — added**: `gui-build-fedora` builds the GUI in a
  `fedora:latest` container (`dnf install gtk3-devel webkit2gtk4.1-devel`), `make gui`
  auto-adds `-tags webkit2_41`, then runs the gui tests + uploads the binary. Fedora
  because Rocky/RHEL 9 has no webkit2gtk4.1-devel (only the older 4.0 API); Fedora is
  RHEL upstream and ships the 4.1 API our builds actually use. Runtime deps documented
  in `docs/GUI.md`.
- Merge PR #1 when the user is ready (currently open, feature→master).

## Original TODO (now largely done — kept for reference)

3. **Frontend: dark launch/connect screen** (`gui/frontend/index.html`,
   `gui/frontend/src/main.js`). Near-black bg (#0d1117), big centered logo,
   connection form (all fields above; API key `type=password`), Connect button,
   inline connect errors. Copy `defilade-logo.png` (repo root, 1.6MB) into
   `gui/frontend/public/` so Vite ships it (vendored map JS already lives in
   `public/vendor/` for the same reason — non-module scripts must be in public/).
   Call the `Connect` binding from `../wailsjs/go/main/App.js`.
4. **Frontend: console dashboard + scan feedback + dark map**. After connect:
   top bar (cluster name + health dot + Run Scan / Cancel buttons), left sidebar
   snapshot list (existing `ListSnapshots`), center Cytoscape map **restyled for
   dark bg** (adjust node/edge/group/tier colors in the cytoscape `style` array in
   main.js — currently light), and a task-output panel streaming `scan:progress`
   events (timestamped lines, live pulse), `scan:done` → refresh list + load new
   map, print the terrain-handling reminder after each scan. Wire events with
   `EventsOn('scan:progress'|'scan:done'|'scan:error', ...)` from
   `../wailsjs/runtime/runtime.js`. Build a `RunScan({Window:"336h",Scope:[...],...})`
   call from the Run Scan button; Cancel calls `CancelScan()`.
   - Existing frontend (viewer) is the starting point: `gui/frontend/index.html`
     + `gui/frontend/src/main.js` already render the map and list. Add the
     connect screen as the initial view; swap to console on connect success.
   - Update `gui/frontend_test.go` markers (it greps the source for expected
     strings) to include the new connect/scan UI (e.g. "Connect", "scan:progress").
5. **Build/test/commit/push**: `make gui` (Rocky needs the `-tags webkit2_41`
   the Makefile adds automatically), `cd gui && go test ./...`, root
   `go test ./...`, gofmt clean, commit, `git push`. PR #1 is open
   (feature→master); pushing updates it and re-runs CI (gui-build matrix +
   race-test). CI is currently green.

## RHEL requirement (user, 2026-07-03)

Must build/run on RHEL-family, not just Debian/Ubuntu. Status:
- **Build**: already works on Rocky 10 (this dev box) via `make gui` — the
  Makefile probes `pkg-config --exists webkit2gtk-4.1` and adds `-tags webkit2_41`.
  `docs/GUI.md` documents `dnf install webkit2gtk4.1-devel gtk3-devel`.
- **CI**: `.github/workflows/ci.yml` gui-build runs ubuntu/macos/windows only
  (ubuntu uses apt `libwebkit2gtk-4.1-dev`). TODO if desired: add a Rocky/Fedora
  container job to CI so RHEL build is continuously verified. Not yet done.
- **Runtime**: a built binary needs libwebkit2gtk-4.1 + libgtk-3 present at run
  time on the target RHEL box. Document in `docs/GUI.md` runtime deps (the
  `-devel` packages are build-time; runtime needs `webkit2gtk4.1` + `gtk3`).

## Environment / build notes

- Go at `/home/phill/.local/go/bin`; Wails CLI at `$HOME/go/bin` (`wails v2.12.0`).
  Prefix commands: `PATH="$PATH:/home/phill/.local/go/bin:$HOME/go/bin"`.
- Use `GOCACHE=/tmp/defilade-go-cache` for go commands (box is 4GB RAM; OOM=exit137).
- `gui/frontend/dist` is gitignored; `go:embed all:frontend/dist` needs it, so the
  gui module only compiles after `wails build`/`make gui` regenerates it. CI builds
  before testing the gui module for this reason.
- **This box is headless** — can build but cannot visually verify the GUI renders,
  the connect form works, or the scan feedback looks right. That's manual QA on a
  machine with a display (checklist in `docs/GUI.md`). Do not report the GUI "done"
  on a successful build alone.
- Fake grid for exercising scans without a real ES:
  `go run ./testdata/fakees -port 9299 -variant 1`, then in the GUI connect to
  `http://127.0.0.1:9299` with any base64 api key (e.g. `dGVzdDp0ZXN0`).
