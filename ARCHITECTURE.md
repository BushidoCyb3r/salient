# Architecture

This document explains how Salient is put together and, more importantly, *why*.
It is written for a new contributor: every claim here should be checkable against
the code, so package paths are cited throughout (`internal/...`). Start with the
[README](README.md) for what Salient does from an operator's seat; this document
covers the design rationale underneath it.

## Mission and northstar

Salient builds a common operational picture of the network domain **passively**.
It connects read-only to Elasticsearch, aggregates the Zeek telemetry a Security
Onion grid has already collected, and turns observed traffic into a scored
dependency graph. It never scans, never probes, and never writes to the grid.
The whole point is to let a hunt team understand unfamiliar terrain without
tipping off an adversary or disturbing a fragile deployment.

One rule organizes the entire codebase: **the observed graph is the primary
truth.** What hosts actually talked to what, over the selected window, as the
sensors saw it — that is the map. Operator artifacts (asset-inventory CSVs,
exported device configs) never become a competing source of truth. They *overlay*
and *reconcile against* the observed graph: they add labels, confirm inferences,
and raise flags where the declared world and the observed world disagree. A
declared config can annotate a gateway or contradict a role, but it can never
mint a node the sensors never saw. This is why config ingestion is deliberately
not a topology-drawing feature — see `docs/config-ingest.md` and
`internal/netconfig`.

## The evidence-honesty contract

The load-bearing design rule is that **nothing is asserted beyond what the
evidence supports.** Salient is a hunting tool; a confident wrong answer is worse
than an admitted gap. Several concrete mechanisms enforce this, and they recur
across packages:

- **Evidence levels on edges** (`internal/graph/evidence.go`). Every dependency
  edge carries an `EvidenceLevel`: `protocol-confirmed` (Zeek named the
  application protocol), `responder-confirmed` (the responder demonstrably took
  part — an established conn state or responder payload bytes), or `port-only`
  (a SYN-only, rejected, or unanswered attempt). Port-only edges stay in the
  snapshot as hunt context but **never** influence terrain scoring, role
  inference, or centrality. A scan cannot mint a fake service provider out of a
  port scan. On real grids roughly 90% of raw connection attempts are port-only
  noise, correctly excluded.

- **The Caveat mechanism** (`internal/netconfig`). When a parsed firewall rule
  uses semantics v1 does not fully model (discontiguous wildcard masks,
  object-groups, `established`, and so on), the parser sets a non-empty `Caveat`
  on the rule instead of guessing. A caveated rule is **never** allowed to
  produce a verdict — it is counted as skipped (`PolicyResult.SkippedRules`),
  and any device that had skipped rules has its finding confidence downgraded
  from `"full"` to `"partial"`, stated on every finding derived from it
  (`internal/netconfig/policy.go`). Better to say "I couldn't honestly judge
  this rule" than to emit a wrong compliance verdict.

- **Warnings are surfaced, not swallowed.** Every reconciliation result
  (`InventoryResult`, `PolicyResult` in `internal/netconfig`; the reconcile and
  drift paths likewise) carries a `Warnings` slice. Unknown constructs, missing
  datasets, and skipped rules degrade to named warnings that reach the operator,
  never silent drops.

- **Declared diffs are re-derived per snapshot, never persisted stale.** When
  device configs are ingested, only the sanitized declared model is stored
  (`salient-data/declared.json`, devices only). The inventory and policy diffs
  are recomputed against whichever snapshot is currently loaded, so a diff can
  never drift out of sync with the terrain it describes.

## Module map

**`internal/escli`** — the read-only Elasticsearch access layer. Every field
name and index pattern lives in a `FieldMap` (`fieldmap.go`) that maps Salient's
abstract field concepts onto a deployment's concrete ECS/Zeek names. This exists
because a wrong field name fails *silently* on Elasticsearch (empty aggregation
buckets, not an error), so a version mismatch must be fixable with
`--fieldmap custom.yaml` rather than a rebuild. The client only ever issues
reads (search, field_caps, resolve, privilege checks) and verifies at connect
that its API key is genuinely read-only (`client.go`, `CheckWritePrivileges`).

**`internal/graph`** — the core data model and the pipeline that turns observed
edges into a scored, role-typed dependency graph. This is the single source of
truth: a `Snapshot` is what gets persisted, and every report and map is a pure
function of a `Snapshot`. `TerrainAddr` (`types.go`) excludes traffic artifacts
(multicast, broadcast, loopback, link-local) from ever being ranked as hosts;
`infer.go` derives conservative role hypotheses that stay `Unknown` when the
evidence is thin.

**`internal/score`** — key-terrain (MRT-C) ranking. Uses gonum for PageRank and
betweenness; centrality is never hand-rolled. The composite score
(`internal/config/defaults.go`) is 40% critical-service **dependents** (distinct
hosts depending on this node for auth/DNS/file/database), 25% **PageRank**
(dependency centrality, auth and DNS edges weighted 3×), 20% **betweenness**
(chokepoint value), and 15% **subnet spread** (how many client subnets depend on
it). Scores are min-max normalized within the snapshot and ranked descending.
Each rank ships with its score-driver evidence, so a rank is never a bare number.

**`internal/mapview`** — derives briefing-map models from snapshots and depends
only on the snapshot model, never on `escli`, so any map re-renders offline. It
produces an overview model (each real VLAN as a box, dependencies bundled between
segments), a focused/drill-in model (full detail for one segment), and the
segment-flow backbone. It also synthesizes gateway placement and stamps the
declared-gateway overlay when a config ingest confirms an inferred gateway.

**`internal/snapshot`** — snapshot persistence, artifact indexing, and drift
comparison. Listings derive from immutable snapshot files (no shared
read-modify-write index), and reads are bounded against decompression bombs.
Drift compares two snapshots and reports what appeared, vanished, changed role
or rank, or began providing a new service dependency.

**`internal/reconcile`** — asset-inventory CSV reconciliation. A pure function of
snapshot + parsed CSV, producing undocumented hosts, documented-but-silent
assets (distinguished from sensor blind spots via `InBlindSpot`), and role
contradictions. The CSV parser is forgiving (header autodetection by keyword)
and treated as a trust boundary (`fuzz_test.go`).

**`internal/netconfig`** — declared-config ingestion. Parses Cisco IOS
running-config text (`cisco.go`) and UniFi controller API JSON (`unifi.go`) into
one normalized `DeclaredDevice` model (`types.go`) the diffs share; the diffs
never see vendor specifics. `inventory.go` reconciles declared devices against
the observed snapshot (device matches, gateway confirmation, silent subnets,
undeclared CIDRs); `policy.go` evaluates observed edges against each device's
bound rulesets. Two properties are worth internalizing:

  - **Secret whitelisting.** Both parsers extract only a whitelisted subset of
    fields. Secret-bearing directives — IOS enable secrets, SNMP communities,
    TACACS/RADIUS keys, usernames; UniFi `x_passphrase`, `x_authkey`, any `x_*`
    field — are never in the whitelist and so can never enter the model. Raw
    config text is never persisted; the uploaded file is read, diffed, and
    discarded, and only the sanitized derived model is written.

  - **Traversal-only policy scoping.** A ruleset judges a flow only when its
    source and destination sit on *opposite sides of the enforcement point*
    (`policy.go`). Same-subnet flows switch locally and never reach the
    device's ACL, so evaluating them would produce a verdict the enforcement
    point never actually renders — an honest "I don't govern this" beats a
    fabricated pass/fail. Only cross-subnet flows are judged.

**`internal/hunt`** — investigation-lead building (`leads.go`). Composes
already-computed Service Authority, drift, and reconciliation data into one
deterministic, prioritized queue. It **never** produces a maliciousness
probability: ordering is an explicit multi-key sort over named facts (reason
priority first, then evidence strength, client count, subnet spread, terrain
rank). Reasons are a fixed vocabulary (`policy-denied`, `contradicted`, new/
displaced provider, and so on) the operator can reason about directly. `oql.go`
emits a minimal Security Onion Hunt (OQL) query for each lead.

**`internal/devices`** — the operator registry. Persists device links (several
IPs merged into one named device), labels, role overrides, pins, declared
segments, and approved providers to `salient-data/devices.json`, surviving
rescans. (The ingested declared-config model is stored separately, in
`salient-data/declared.json` — see the config-ingest flow below.)

**`internal/assist`** — optional, explicitly enabled model assistance for the
CLI `analyze` command and desktop device tagging. It never contacts
Elasticsearch and is not used by scan or map. Remote endpoints require HTTPS
and an explicit egress acknowledgement (`--allow-network-data-egress`); without
it the request is refused (`client.go`). Only capped node/edge summaries are
sent, never raw events or credentials. Analysis findings must cite existing
snapshot IDs, and tag suggestions stay separate from observed evidence until an
operator accepts them.

**`internal/report`** — pure renderers over a snapshot: analyst HTML, SVG maps,
drift and reconcile HTML, and GraphML.

**`internal/safefile`** — writes sensitive local artifacts without following
destination symlinks or leaving partial files behind (directory-relative
`os.Root` operations, 0600 files in 0700 dirs on POSIX).

**`internal/scan`** — the shared scan pipeline. Both the CLI `scan` command and
the desktop console drive it through `Run`, differing only in the report
callback. A canceled scan is fatal: it writes no snapshot, report, or map rather
than announcing an incomplete run as complete.

**`cmd/salient`** — the command-line interface (test-connection, discover, scan,
list, view, report, map, diff, reconcile, declared, mission, stability, analyze,
and shell completion).

**`gui/`** — the Wails desktop console, the primary interface. It is a
**separate Go module** (`gui/go.mod`). Wails generates the backend bindings in
`gui/frontend/wailsjs`; `make gui` regenerates them, and CI rejects drift. The
hand-written `gui/frontend/src/bindings.js` facade is the frontend import seam:
it uses the generated bindings in the native app and provides safe no-op
behavior for browser tests and the static demo harness.

## Key data flows

**Scan.** `escli` aggregates a window server-side (no raw-event download) →
`graph` builds and scores the dependency graph → `snapshot` persists it →
`mapview`/`report` render maps and reports → the GUI or CLI presents them. Every
downstream artifact is a pure function of the snapshot, so anything can be
reproduced offline without reconnecting to the grid.

**Config ingest.** Uploaded files → `netconfig` parsers (secrets stripped, raw
text never persisted) → sanitized `[]DeclaredDevice` written to
`salient-data/declared.json` (devices only) → inventory and policy diffs
**re-derived against each loaded snapshot** → map badges (declared gateways,
undeclared-subnet markers) and Hunt Leads (`policy-denied`, priority 0). Because
the diffs are recomputed per snapshot, the declared world always reconciles
against current observed terrain.

## Security posture

- **Read-only, verified.** The API key's privileges are checked at connect and
  loud warnings are raised on write-class grants, on check errors, and on
  indeterminate results (`internal/escli/client.go`).
- **TLS posture warnings.** Plaintext `http://` is refused except against
  loopback, and insecure-TLS is an explicit, surfaced operator choice.
- **Secrets never enter the model.** `netconfig` whitelists fields; secret-
  bearing directives are structurally excluded, and raw configs are never
  written to disk.
- **Keys stay in memory.** Elasticsearch and model API keys are never written to
  disk; tag sidecars record only endpoint host, model, timestamp, and validated
  suggestions.
- **No external runtime.** Frontend JS is vendored (no CDN, no telemetry); the
  CLI is a static self-contained binary.
- **Local artifacts are guarded** (`internal/safefile`): 0600/0700, symlink-safe
  writes, bounded snapshot reads.

## Known limits

These are deliberate v1 boundaries, chosen to keep every output honest. Most are
documented in `internal/netconfig/policy.go` and `docs/config-ingest.md`.

- **Per-device policy evaluation only.** Salient evaluates each device's rules
  against observed flows; it does **not** simulate multi-device L3 paths (a
  reachability matrix). Partial configs would silently produce wrong
  reachability — the worst failure mode for an evidence-honest tool — so this is
  left to a possible future version.
- **Intra-subnet blindness for policy diff.** Same-subnet flows never traverse
  the enforcement point, so they are never judged (see traversal-only scoping
  above).
- **Passive-only visibility.** No traffic means no verdict; an absence of
  observed flows is **not** proof of compliance or of a blocked path. Unsensed
  east-west traffic and empty windows are blind spots, not silence.
- **Source ports are not evaluated** in policy verdicts.
- **Exact Hunt OQL execution is not live-validated.** The generated queries are
  intentionally minimal, and their ECS field names were confirmed against the
  live Elasticsearch mappings. They have not yet been executed through a
  Security Onion Hunt UI's OQL parser (`internal/hunt/oql.go`); confirm that
  final syntax path before relying on them operationally.
