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

- **Phase 0 implementation** (`test-connection`, `discover`) — done. Live-grid
  field-map verification is still pending.
- **Phase 1** (`scan` → scored snapshot + analyst report) — done and committed
  at `b6019c6`.
- **Phase 1.5** (briefing maps) — implementation committed at `246ca9b`.
  Additional CLI validation and artifact-handling tests are uncommitted.
  Offline yEd/draw.io round-trip and cold-reader homelab validation remain
  manual acceptance checks.
- **Phase 2** (drift) — repository implementation complete but uncommitted:
  deterministic node/edge/rank/full-role-set comparison, HTML + JSON reports,
  `diff --map` drift overlays, low-volume critical-drift preservation, and CLI
  tests. The live-homelab new-server exercise remains pending.
- Optional snapshot-only model analysis with deliberate opt-in network egress
  is approved and currently uncommitted. Remote use requires HTTPS and the
  explicit `--allow-network-data-egress` acknowledgement.
- The working tree also contains expected Graphify integration/output. Inspect
  `git status` before editing and do not discard or overwrite unrelated changes.
- **Phase 3** (reconciliation) — implemented: forgiving CSV asset-list
  ingest, documented-silent/observed-undocumented/role-contradicted lists,
  HTML + JSON reports, `reconcile --map` flagged briefing maps with
  asset-doc segment names enriching group labels. Handing the report to a
  real supported unit's staff remains the acceptance check.
- Next is **Phase 4 hardening** and/or live-grid validation of Phases 0-3.
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
