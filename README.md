# Defilade

**Passive terrain-dependency analyzer and network-map generator for Security Onion grids.**

*Defilade* is the defensive posture of occupying protected ground — shielded from observation and fire — from which you observe and map the terrain before you're exposed. Defilade the tool is what the defender runs *from* that covered position: passive, read-only, no active scanning that would give away presence or disturb the network. The name describes the operator's posture, not the tool's output.

Defilade is a **read-only Elasticsearch client**. It queries the Zeek logs already aggregated on a Security Onion manager and produces a typed dependency graph, a ranked key-cyber-terrain report with evidence attached to every ranking, briefing-ready network maps, drift detection between snapshots, and a doc-vs-reality reconciliation report. Primary use case: CPT/hunt-team terrain familiarization in the first 72 hours on an unfamiliar network.

> **Project status: Phase 0 (ground-truth validation).** Only `test-connection` and
> `discover` exist so far — deliberately. The default field map is an *unverified
> assumption* about how Security Onion maps Zeek fields to ECS, and a wrong field map
> fails silently. No graph code gets built until `discover` output from a real grid is
> recorded in `docs/FIELDMAP.md`. See `DEFILADE_PLAN.md` §12.

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
```

`discover` reports which Zeek datasets exist (conn, dns, kerberos, smb, …), document
counts, reporting sensors, and whether MAC fields survived the ECS mapping. If any
field names differ from the defaults, pin them with `--fieldmap custom.yaml`
(see `docs/FIELDMAP.md`).

## Hard constraints

- Pure Go, no cgo, single static binary (linux/amd64, darwin/arm64, windows/amd64: `make cross`).
- **Read-only against Elasticsearch.** The only writes are to the local filesystem.
- Fully offline once pointed at the grid: no external calls, no telemetry, no CDN assets.
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

See `DEFILADE_PLAN.md` for the full architecture and phased plan. Current tree:

```
cmd/defilade/          CLI (cobra): test-connection, discover
internal/config/       every tunable default — no magic numbers inline
internal/escli/        read-only ES client, FieldMap, query builders
docs/DEPLOYMENT.md     read-only API key + so-firewall allow-list steps
docs/FIELDMAP.md       field-map verification worksheet (Phase 0 output)
```
