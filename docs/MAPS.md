# Briefing maps

`defilade map --snapshot FILE [--format html|svg|graphml]` renders a
subnet-grouped, tiered dependency map from a stored snapshot. Maps are a pure
function of the snapshot (`internal/mapview`) — no ES access, fully offline,
re-renderable anytime.

## What these maps are — and are not

**L3 logical dependency maps derived from observed traffic.** They show real
observed dependencies, how heavy they are, and which nodes are key terrain —
annotated with criticality, something a hand-drawn Visio never has.

**Not physical topology.** Flow data cannot see switches, physical links,
port assignments, or any device that never talks across a monitored segment.
The one concession: gateway placement via MAC-convergence inference where
sensor placement allows it (see below) — and even that is drawn dashed and
labeled "inferred" when there's no L2 evidence, never presented as fact.

## Reading the map

- **Boxes** are subnet groups (default `/24`, `--group-prefix` to change).
  Hatched red boxes are **blind spots**: in scope, zero observed traffic.
- **Rows within a box** are tiers, top to bottom: **Core** (gateways, DCs,
  DNS, network gear) → **Service** (file/db/web/jump/mail) → **Client**
  (printers, cameras, workstations, everything else).
- **Diamond/dashed nodes** are gateways. Solid = MAC-convergence evidence
  observed on this grid. Dashed "gateway (inferred)" = synthesized from
  cross-subnet traffic because no MAC evidence exists — never observed fact.
- **Node roles** include `NetworkGear` for hosts serving controller/switch/AP
  protocols (CAPWAP, PAPI, Smart Install, TACACS+). Clicking a node also shows
  its observed **MAC** and decoded **vendor** when captured (a host's own NIC;
  gateway MACs are excluded so a router's MAC is never mis-attributed).
- **Amber-bordered nodes** are operator-**pinned** (console): a host forced to
  render individually regardless of rank. **Violet border** = linked to a named
  device.
- **"N workstations" nodes** are aggregated: `Unknown`-role, low-composite
  clients collapse into one meta-node per subnet so the map stays readable.
  Full detail is always in the analyst HTML report, one click away in the
  interactive map.
- **Edges** are bundled by (group, group, service class) and colored by a
  fixed palette, same in every product:

  | Class | Color | Ports |
  |---|---|---|
  | auth | red-orange | kerberos, ldap |
  | name resolution | blue | dns |
  | file | green | smb |
  | database | purple | mssql, mysql, postgres, oracle |
  | web | gray | http, https |
  | admin (RDP/SSH) | yellow | rdp, ssh |
  | other | light gray | everything else |

- Edges below `--min-conns` (default 5) are hidden on the map only — never
  removed from the snapshot or the analyst report.
- `--focus CIDR` restricts the map to one enclave when the full grid exceeds
  the readability target (~60 elements). `--focus private` / `--focus public`
  restrict to private (RFC1918) or non-private address space instead of one
  CIDR; unlike a CIDR focus, these are scope filters and still condense to an
  overview when oversized.

## Automatic overview mode (broad scopes)

An unfocused map that exceeds 120 elements is automatically condensed into a
**briefing overview** near the 60-element target instead of rendering an
unreadable wall:

- **private (RFC1918) space gets the groups; everything else — internet
  peers, multicast, broadcast — collapses into one "external" box.** The
  briefing shows your terrain, not the internet's. Multicast and broadcast
  addresses are never shown as individual hosts regardless of score rank;
- internal subnet groups keep the operator's true grouping prefix (`/24` by
  default) — they are never coarsened into supernet boxes that name no real
  segment; when the group count overflows the budget, the least important
  groups merge into an honest "other internal networks" bucket;
- the top 20 hosts by score rank (excluding multicast/broadcast artifacts)
  stay individually visible; **every other host — including lower-ranked
  servers — collapses into one "N other hosts" aggregate per group**;
- **console overrides:** right-click **Pin to map** forces any collapsed host
  to stay visible, and the **show all private hosts** checkbox promotes every
  RFC1918 host to its own node (external peers still collapse), capped at 1500
  with a finding when it clips. In show-all-private mode every connection
  between the visible hosts is drawn — the edge budget is not applied — and
  every private VLAN keeps its own box (no group cap, so a lightly-populated but
  real segment is never lumped into "other internal networks"), since it is an
  explicit "show everything" view;
- at most one gateway per group survives (observed L2 candidates win by
  distinct-IP count);
- only the strongest bundled edges that fit the element budget remain, with
  edges touching top-ranked terrain kept first. Drift/reconcile-flagged nodes
  and edges are retained ahead of everything else and are never trimmed; if
  flagged items alone exceed the budget, a finding says how many appear only
  in the report.

The overview is a briefing product, **not a complete topology**: it never
shows every host or dependency. The snapshot itself is untouched — re-render
any enclave in full detail:

```sh
./bin/defilade map \
  --snapshot defilade-data/snapshots/<timestamp>.json.gz \
  --focus 10.10.40.0/24 \
  --format html
```

A finding on the map states the original and reduced element counts whenever
overview reduction ran. `--focus` maps keep the old behavior: full detail,
with a warning above 120 elements.

## Export formats

- `--format html` (default): self-contained interactive map, Cytoscape.js +
  fcose/dagre layouts embedded via `go:embed` — no network, opens in any
  browser. Layer toggles (criticality heat, sensor coverage, edge labels),
  click a node for its role evidence.
- `--format svg`: deterministic, server-rendered, no browser needed. Drops
  straight into a PowerPoint/Word slide.
- `--format graphml`: subnet groups as nested `<graph>` elements — the
  structure yEd and draw.io both import as native group nodes.

## Importing GraphML into draw.io or yEd (offline)

1. Generate the file: `defilade map --snapshot FILE --format graphml > map.graphml`
2. **draw.io** (desktop, offline): File → Import from → Device → select the
   `.graphml` file. draw.io reads the nested `<graph>` elements as swimlane
   groups; nodes land inside their subnet's container. Re-layout with
   Arrange → Layout → Vertical Tree for a tiered look, or leave as-is and
   hand-adjust. Export to `.vsdx` via File → Export as → VSDX if Visio is a
   hard requirement.
2. **yEd** (desktop, offline): File → Open, select the `.graphml`. yEd
   respects the nested-graph grouping natively as folder nodes. Use
   Layout → Hierarchical for a tiered view, or Layout → Organic for the
   fcose-equivalent look. yEd's own GraphML dialect (`y:` extensions) is not
   emitted — yEd still imports plain GraphML fine, it just won't carry
   yEd-specific styling from Defilade; style after import.

Both apps are offline desktop tools, so this path stays air-gap safe.

## Drift-highlighted maps

```sh
defilade diff --from older.json.gz --to newer.json.gz --format html --map
```

This writes the HTML drift report and a sibling `.diff.map.html` briefing map.
New nodes and critical edges have green borders, vanished nodes and critical
edges are ghosted, and significant rank changes have amber borders. The
**drift highlights** layer toggle removes these visual overrides without
hiding the underlying terrain.

Vanished nodes and edges come from the older snapshot and remain visual
context only; the newer snapshot stays the authoritative current state.

## Reconciliation-flagged maps

```sh
defilade reconcile --snapshot snap.json.gz --assets assets.csv --format html --map
```

This writes the doc-vs-reality report and a sibling `.reconcile.map.html`
briefing map. Observed-but-undocumented hosts get red borders, hosts
contradicting their documented role get amber double borders, and
documented-but-silent assets are ghosted into their subnet group — including
inside hatched blind-spot boxes, where "silent" may just mean "unobserved".
Asset-list VLAN/segment names enrich the subnet-group labels.

The asset CSV is parsed forgivingly: header names are autodetected
(ip/address, host/name, role/function, vlan/segment/site), quoting is lazy,
and rows without a parseable IP are skipped with a warning instead of
failing the run.
