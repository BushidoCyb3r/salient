# Key-terrain criticality maps

`defilade map --snapshot FILE [--format html|svg|graphml]` renders a
subnet-grouped, tiered dependency map from a stored snapshot. Maps are a pure
function of the snapshot (`internal/mapview`) — no ES access, fully offline,
re-renderable anytime.

## What these maps are — and are not

**Criticality views of L3 logical dependencies derived from observed traffic.**
They communicate the ranked key terrain: larger, hotter nodes are more critical,
and their evidence explains why. They are not intended to reconstruct a network
diagram.

**Not physical topology.** Flow data cannot see switches, physical links,
port assignments, or any device that never talks across a monitored segment.
The one concession: gateway placement via MAC-convergence inference where
sensor placement allows it (see below) — and even that is drawn dashed and
labeled "inferred" when there's no L2 evidence, never presented as fact.

## Reading the map

- **Boxes** are subnet groups (default `/24`, `--group-prefix` to change). In
  the desktop app the **Segments** panel overrides this with your real subnets:
  declare CIDRs (e.g. split `10.10.40.0/24` into `10.10.40.0/25` +
  `10.10.40.128/25`, or merge several `/24`s into one supernet) and each host
  falls into the most-specific declared segment; undeclared hosts still group by
  `/24`. Hatched red boxes are **blind spots**: in scope, zero observed traffic.
- **Layouts** (desktop): *grid* (default criticality view), *organic*
  (force-directed), and *topology* (optional declared-device cross-check).
- **Topology layout (secondary)**: an optional declared-design cross-check — external box up top, VLAN
  boxes banded by traffic below, router pinned atop each box — extended with the
  physical hierarchy *you declare*. Tag a device's network layer (its type:
  boundary/router/switch) and give it the IP **ranges it owns** (device card →
  "owns ranges"); it collapses to one focus node — however many IPs/VLANs it
  spans — placed in a boundary/router/switch band between the external box and
  the VLAN rows, and every VLAN whose range it owns threads up through it.
  Routing hops render **dashed** — declared, not observed, since flow data
  cannot see L2 fabric. Layer order (switch → router → boundary) sets the tiers;
  no uplinks to declare. It is useful when an operator already has a declared
  design to compare, but it is not the resting view or a substitute for the
  key-terrain ranking.
- **Node size and criticality heat** encode the composite terrain score. Heat is
  on by default in the overview so high-impact systems dominate before the
  operator selects anything.
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

## Automatic segment-flow map (broad scopes)

An unfocused map that exceeds 120 elements is automatically condensed into a
**segment-flow overview** — a picture of logical flow *between* segments,
navigable down to host detail — instead of a flat wall of nodes:

- **every real internal VLAN keeps its own box.** Segments use the operator's
  true grouping prefix (`/24` by default) and are never coarsened into supernet
  boxes or lumped together — a lightly-populated but real segment (e.g. a 2-host
  `10.10.60.0/24`) still gets its own box. Only a pathological number of VLANs
  (more than `MapSegmentMaxGroups`, 64) overflows the least-active into "other
  internal networks". Every public/multicast/broadcast peer collapses into one
  "external" box so the map shows your terrain, not the internet's;
- **each box shows its own top hosts, not a global top-N.** The highest-ranked
  `MapSegmentTopHosts` (5) hosts of *each* segment stay named and individual;
  the rest collapse into one **"N more hosts"** chip for that segment. A busy
  VLAN can no longer monopolise the map and leave every other segment a blob;
- **the default view is the high-level backbone: one aggregated
  segment→segment line per VLAN pair**, colored by the dominant service class
  and sized by volume — logical flow at a glance, not the unreadable N² host
  mesh. Host-level detail is revealed on demand: **click a host** to light its
  own flows, **click a VLAN box** to light everything that segment talks to,
  **click empty canvas** to return to the backbone. The **show all flows** layer
  draws every host edge at once (dense);
- **drill into a segment:** double-click a VLAN box (marked ▸) to re-render
  focused on that CIDR — every host, intra-segment flow, gateways — then
  **← overview** to return. The overview defaults to the grid criticality view;
  organic and topology remain explicit operator choices;
- at most one gateway per segment survives (observed L2 candidates win by
  distinct-IP count);
- **console overrides:** right-click **Pin to map** forces any collapsed host to
  stay visible in the overview; **show every private host (dense)** is an escape
  hatch that promotes every RFC1918 host to its own node and draws every
  connection between them (capped at 1500, off by default — the segment view is
  usually clearer).

The segment-flow map is a briefing product, **not a complete topology**: the top
level summarises. The snapshot itself is untouched — drill into a segment, or
re-render any enclave in full detail from the CLI:

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

In the desktop console, reconcile takes the asset list two ways: **Load asset
CSV…** (a spreadsheet export, columns autodetected as above) or **Enter
manually…**, which opens an in-app grid with the columns pre-loaded (IP,
hostname, role, VLAN/segment). Both feed the identical parse-and-compare path —
manual entry is just a typed-in CSV for when a handful of hosts doesn't warrant
a file.

The asset CSV is parsed forgivingly: header names are autodetected
(ip/address, host/name, role/function, vlan/segment/site), quoting is lazy,
and rows without a parseable IP are skipped with a warning instead of
failing the run.
