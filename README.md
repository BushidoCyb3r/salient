# Defilade

**Passive terrain-dependency analyzer and network-map generator for Security Onion grids.**

*Defilade* is the defensive posture of occupying protected ground — shielded from observation and fire — from which you observe and map the terrain before you're exposed. Defilade the tool is what the defender runs *from* that covered position: passive, read-only, no active scanning that would give away presence or disturb the network. The name describes the operator's posture, not the tool's output.

Defilade is a **read-only Elasticsearch client**. It queries the Zeek logs already aggregated on a Security Onion manager and produces a typed dependency graph, a ranked key-cyber-terrain report with evidence attached to every ranking, briefing-ready network maps, drift detection between snapshots, and a doc-vs-reality reconciliation report. Primary use case: CPT/hunt-team terrain familiarization in the first 72 hours on an unfamiliar network.

> **Project status: all planned phases (0–4) implemented; live-grid validation pending.** `scan` aggregates the window
> server-side, builds and scores the dependency graph, and writes a snapshot,
> analyst report, and briefing map. Stored snapshots can also be rendered offline as
> HTML, SVG, or GraphML; `diff` compares snapshots and emits HTML or JSON drift
> reports; `reconcile` diffs a documented asset list (CSV) against observed
> reality. Optional model-assisted analysis is available only through the explicit
> snapshot-only `analyze` command. `diff --map` and `reconcile --map` also write
> interactive maps with changed or contradicted terrain highlighted. Unfocused maps
> above 120 elements auto-condense to a ~60-element briefing overview — only
> top-ranked terrain and the strongest dependencies stay individually visible
> (never a complete topology); use `--focus CIDR` to re-render any enclave in
> full detail (see `docs/MAPS.md`). The default field map is still an *unverified assumption* about how
> Security Onion maps Zeek fields to ECS — run `discover` against your grid and record
> ground truth in `docs/FIELDMAP.md` before trusting a scan. Wrong field maps fail
> loudly by design.

## 60-second quickstart

```sh
make build

# Keep credentials out of shell history:
export DEFILADE_ES_URL="https://so-manager:9200"
export DEFILADE_API_KEY="<base64 id:key — see docs/DEPLOYMENT.md for read-only key creation>"

# 1. Can we reach and read the grid? Is the key really read-only?
./bin/defilade test-connection --ca-cert grid-ca.pem

# 2. What does this grid actually contain?
./bin/defilade discover --ca-cert grid-ca.pem --window 168h

# 3. Scan: aggregate 14 days, score terrain, write snapshot + report
./bin/defilade scan --ca-cert grid-ca.pem --window 336h \
    --scope 10.0.0.0/8 --tz America/New_York

# Re-render or export a stored snapshot
./bin/defilade list
./bin/defilade view
./bin/defilade report --snapshot defilade-data/snapshots/<ts>.json.gz --format graphml
./bin/defilade map --snapshot defilade-data/snapshots/<ts>.json.gz --format svg > map.svg
./bin/defilade diff --from defilade-data/snapshots/<older>.json.gz \
    --to defilade-data/snapshots/<newer>.json.gz --format html --map

# Reconcile the supported unit's asset list against observed reality
./bin/defilade reconcile --snapshot defilade-data/snapshots/<ts>.json.gz \
    --assets unit-assets.csv --format html --map

# Optional: analyze a stored snapshot with a local compatible endpoint
./bin/defilade analyze --snapshot defilade-data/snapshots/<ts>.json.gz \
    --endpoint http://127.0.0.1:11434/v1/chat/completions --model local-model
```

`discover` reports which Zeek datasets exist (conn, dns, kerberos, smb, …), document
counts, reporting sensors, and whether MAC fields survived the ECS mapping. If any
field names differ from the defaults, pin them with `--fieldmap custom.yaml`
(see `docs/FIELDMAP.md`).

A native desktop operator console (Linux/macOS/Windows) is also available — see
`docs/GUI.md`. It connects to a grid, runs scans with live progress, and browses
and exports the resulting snapshots and maps in a real window. Model-assisted
`analyze` remains CLI-only.

## Hard constraints

- Pure Go, no cgo, single static binary (linux/amd64, darwin/arm64, windows/amd64: `make cross`).
- **Read-only against Elasticsearch.** The only writes are to the local filesystem.
- Fully offline by default: no telemetry or CDN assets. The snapshot-only `analyze`
  command may call an explicitly configured endpoint; remote HTTPS endpoints require
  `--allow-network-data-egress` (see `docs/AI.md`).
- Mode 1 deployment only: a binary on an analyst workstation with reach to the manager's ES API. No new servers, containers, agents, or SO config changes.

## Limitations (read before trusting the output)

Stated plainly, because operator credibility comes from stating what the tool can't see:

- **Passive-window blindness.** Defilade sees only what talked during the analysis window. A quarterly job that didn't run is invisible; a decommissioned server and a merely quiet one look identical.
- **Sensor-coverage blindness.** East-west traffic on segments without a sensor never reaches Zeek. In-scope subnets with zero observed traffic are flagged as *possible blind spots*, not proof of silence.
- **L3 logical maps, not physical topology.** Flow data cannot see switches, physical links, port assignments, or devices that never converse across a monitored segment. The maps show real observed dependencies annotated with criticality — the thing a hand-drawn Visio can't be — never physical layout.
- **Gateway inference is inference.** Where MAC fields exist, gateways are placed by MAC-convergence evidence; where they don't, gateways are synthesized per subnet and explicitly labeled "inferred" with a dashed border. The fallback is never presented as observed fact.
- **Roles are evidence-scored guesses.** Seven conservative rules (DC, DNS, file, DB, jump box, web, gateway); everything else is honestly `Unknown` rather than wrongly labeled.

## Artifact handling

Reports and maps describe your network's dependencies and key terrain — **a briefing
map is the single most exfiltration-worthy artifact this tool produces**. Output files
are written 0600 in 0700 directories. Treat every artifact as classified at the level
of the network it describes.

## Repository layout

```
cmd/defilade/          CLI (cobra): test-connection, discover, scan, report, map, diff, reconcile, analyze, list, view
internal/config/       every tunable default — no magic numbers inline
internal/escli/        read-only ES client, FieldMap, query builders
internal/graph/        typed dependency-graph and snapshot types
internal/score/        key-cyber-terrain composite scoring
internal/mapview/      subnet grouping, gateway inference, map simplification/overview
internal/reconcile/    asset-list ingest and doc-vs-reality comparison
internal/report/       analyst reports and HTML/SVG/GraphML map renderers
internal/snapshot/     snapshot save/load/list/diff, and artifact scanning shared by the CLI `view` command and the GUI
internal/assist/       optional snapshot-only model-assisted analysis (`analyze`)
gui/                   native desktop map viewer, separate Wails v2 Go module — see docs/GUI.md
web/                   vendored, embedded JS for the HTML/interactive map (no CDN assets)
docs/DEPLOYMENT.md     read-only API key + so-firewall allow-list steps
docs/FIELDMAP.md       field-map verification worksheet (Phase 0 output)
docs/GUI.md            desktop viewer build steps and manual QA checklist
docs/MAPS.md           map rendering, briefing-overview condensation, --focus
docs/AI.md             `analyze` command: scope, egress guard, threat model
```
