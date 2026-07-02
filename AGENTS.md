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

Claude Code has been doing the implementation work in this repo and keeps
notes on the user's working preferences at
`/home/phill/.claude/projects/-home-phill/memory/` (see `MEMORY.md` there for
the index). Worth a read for anything not covered here.

## Hard constraints (from DEFILADE_PLAN.md — do not violate)

- Pure Go, no cgo, single static binary.
- Read-only against Elasticsearch. The only writes are to the local filesystem.
- Fully offline once pointed at a grid — no external calls, no CDN assets,
  everything embedded via `go:embed` (see `web/`).
- No new servers, containers, agents, or Security Onion config changes.

## Current status (as of the last Claude session)

- **Phase 0** (ground-truth validation: `test-connection`, `discover`) — done.
- **Phase 1** (`scan` → scored snapshot + analyst report) — done, committed.
- **Phase 1.5** (briefing maps, `mapview` package) — in progress, uncommitted
  in the working tree: subnet grouping, gateway synthesis (L2 MAC-convergence
  primary / cross-subnet inferred fallback), simplification pipeline, SVG +
  interactive HTML (Cytoscape/fcose/dagre) + grouped GraphML renderers exist;
  the `map` CLI subcommand and its tests are not yet wired up. Check
  `git log` and `git status` for the exact boundary before continuing —
  this note will drift.
- Every field name in `internal/escli/fieldmap.go` is still `// UNVERIFIED`
  until `discover` has been run against a real homelab grid and
  `docs/FIELDMAP.md` filled in. Don't build Phase 2+ features assuming the
  defaults are correct.

## Build/test

Go isn't on PATH by default in this environment; it's installed at
`~/.local/go/bin`. `export PATH=$PATH:~/.local/go/bin` before `go build`/`go
test`. `make build`, `make test`, `make cross` work once that's set. No C
compiler is installed, so `-race` (used by `make test`) will fail here —
drop `-race` for local runs, or note the gap rather than silently skipping
tests.

## Docs that matter

- `docs/FIELDMAP.md` — field-map verification worksheet, Phase 0 deliverable.
- `docs/DEPLOYMENT.md` — read-only API key + firewall allow-list steps.
- `docs/MAPS.md` — not created yet; owed by Phase 1.5 per the plan (§8.6,
  §12) once the `map` command and yEd/draw.io import walkthrough exist.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
