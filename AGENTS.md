# Defilade — instructions for Codex

Read `/home/phill/.codex/AGENTS.md` first (identity/attribution rules — commit
as `BushidoCyb3r`, never mention an AI vendor). This file is project-specific
context on top of that baseline.

## What this project is

Defilade is a read-only Elasticsearch client that turns Zeek logs on a
Security Onion grid into a scored dependency graph, a key-cyber-terrain
report, and briefing maps. Full spec, architecture, and phased plan:
**`/home/phill/DEFILADE_PLAN.md`** — read it before touching anything
non-trivial, it's the source of truth for scope and constraints. Quickstart
and current status: `README.md` in this repo.

## Hard constraints (from DEFILADE_PLAN.md — do not violate)

- Pure Go, no cgo, single static binary.
- Read-only against Elasticsearch. The only writes are to the local filesystem.
- Fully offline by default — no telemetry or CDN assets, everything embedded
  via `go:embed` (see `web/`). The snapshot-only `analyze` command is the sole
  exception: it may call an explicitly configured endpoint, with an additional
  acknowledgement required for remote network-data egress.
- No new servers, containers, agents, or Security Onion config changes.

## Current status

- **All plan phases (0–4) are implemented and committed on master.**
  Phase 0 `b6019c6`-era, Phase 1 `b6019c6`, Phase 1.5 `246ca9b`+`fdbf60a`,
  Phase 2 (drift/diff) `9c71bf3`, analyze `f0f210f`, Phase 3 (reconcile)
  `a3dcc0d`, Phase 4 (sampled betweenness, CI, cross-build memory guard)
  `7f225c4`, fuzz targets `de2052a`. Working tree should be clean — check
  `git status` before assuming otherwise.
- **Nothing has been pushed to GitHub yet.** The user wanted extensive local
  testing first; that testing is done (see "Pre-push test evidence" below).
  Push when the user says so — remember the identity rules at the top.
- Remaining work is validation, not code: live-grid field-map verification
  and end-to-end exercise against the homelab Security Onion grid,
  yEd/draw.io GraphML round-trip on an offline machine, cold-reader map
  test, handing reconcile output to a real supported unit.
- Every field name in `internal/escli/fieldmap.go` is still `// UNVERIFIED`
  until `discover` has been run against a real homelab grid and
  `docs/FIELDMAP.md` filled in.

## Pre-push test evidence (2026-07-02 session)

Everything below passed; re-run any of it with the harness in
`testdata/fakees/`.

- **End-to-end against a fake ES** (`testdata/fakees/main.go`, stdlib-only):
  `go run ./testdata/fakees -port 9299 -variant 1` then point the real binary
  at `--es http://127.0.0.1:9299`. Serves cluster info, _resolve, _field_caps,
  _has_privileges, and body-sniffed _search aggs (composite edge pages with
  after_key, responder cardinality, datasets, sensors, temporal hist, gateway
  MACs), plus `/v1/chat/completions` for `analyze`. `-variant 2` mutates the
  network (new DB server appears, web server vanishes) — `diff` caught
  appeared/vanished/new-critical-edges exactly; `scan` ranked the new server
  #4 (the plan's Phase 2 acceptance scenario, synthetically).
- **Artifacts:** SVG/GraphML XML-parse clean, every HTML self-contained (zero
  external refs), binary-written files 0600 in 0700 dirs.
- **Egress guards:** remote HTTP refused; remote HTTPS without
  `--allow-network-data-egress` refused; HTTP with the flag still refused;
  loopback allowed.
- **Fuzzing:** `FuzzParseCSV` ~1.9M execs and `FuzzLoadFieldMap` clean; seed
  corpus runs in normal `go test`.
- **Security greps:** only outbound dialers are the ES client and the opt-in
  assist path; embedded web/*.js has no runtime network calls; no telemetry.
- **Gap:** `-race` has never run locally (no C compiler here); CI runs it on
  first push. Live-grid validation still pending.

## Build/test

Go isn't on PATH by default in this environment; it's installed at
`~/.local/go/bin`. `export PATH=$PATH:~/.local/go/bin` before `go build`/`go
test`. `make build`, `make test`, `make cross` work once that's set. No C
compiler is installed, so `-race` (used by `make test`) will fail here —
drop `-race` for local runs, or note the gap rather than silently skipping
tests.

This box has 4GB RAM. Anything that gets SIGKILLed (exit 137) is the OOM
killer, not a code bug: cross-compiles must not run in parallel (`make
cross` already sets GOFLAGS=-p=2), and `go test -fuzz` needs
`-parallel 1` (optionally GOGC=50). Elastic's typedapi/types package is the
usual trigger.

## Docs that matter

- `docs/FIELDMAP.md` — field-map verification worksheet, Phase 0 deliverable.
- `docs/DEPLOYMENT.md` — read-only API key + firewall allow-list steps.
- `docs/MAPS.md` — briefing-map interpretation, export/import, and drift maps.
- `docs/AI.md` — optional model-analysis egress and integrity boundary.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
