# Key-terrain criticality maps

`salient map --snapshot FILE [--format html|svg|graphml] [--output FILE]` renders a
subnet-grouped, tiered dependency map from a stored snapshot. Maps are a pure
function of the snapshot (`internal/mapview`) — no ES access, fully offline,
re-renderable anytime.

## What these maps are — and are not

**Criticality views of L3 logical dependencies derived from observed traffic.**
They communicate the ranked key terrain: larger, hotter nodes are more critical,
and their evidence explains why. They are not intended to reconstruct a network
diagram.

The maps also support rogue-service hunting. Inferred responder roles show what
services hosts actually provide; drift highlights newly appeared hosts, roles,
and dependencies; and reconciliation flags observed behavior that is missing
from or contradicts the asset inventory. Together these identify potential
rogue or malicious service providers for analyst validation.

The **Service Authority** panel lists every sensitive-service provider
(DNS, DHCP, authentication, file, database) observed in the current
snapshot, aggregated from confirmed edges only — client count, strongest
evidence tier, and terrain rank per provider. Click a row for a dependency
dossier (hostname, role, service/port, evidence, client count, first/last
seen). This is the current-snapshot view; drift's new-provider detection
(above) is its across-snapshot counterpart.

**Hunt Leads** turns Service Authority, drift, and asset reconciliation into
one prioritized list: role contradictions and undocumented providers first,
then new providers/services, then sole-observed providers — ordered by
explicit facts (evidence tier, client count, subnet spread, terrain rank),
never a probability score. Each lead includes a one-click Security Onion
Hunt query copy for further validation in Security Onion — Salient
identifies and prioritizes, Security Onion remains the detailed
investigation environment.

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
- **Key-terrain score** is computed from the snapshot dependency graph, then
  ranked descending: 40% distinct critical-service dependents (auth, DNS/name,
  file, DB), 25% PageRank dependency centrality (auth and DNS/name edges count
  3×), 20% betweenness/chokepoint value, and 15% client-subnet spread. Each
  component is min-max normalized inside the snapshot. Multicast, broadcast,
  loopback, and link-local artifacts are excluded from the terrain composite.
  The desktop **Key Terrain** button opens the ranked drawer for the current
  map; collapsed named devices use their strongest member rank and zoom as one
  device node.
- **Rows within a box** are tiers, top to bottom: **Core** (gateways, DCs,
  DNS, network gear) → **Service** (file/db/web/jump/mail) → **Client**
  (printers, cameras, workstations, everything else).
- **Diamond/dashed nodes** are gateways. Solid = MAC-convergence evidence
  observed on this grid. Dashed "gateway (inferred)" = synthesized from
  cross-subnet traffic because no MAC evidence exists — never observed fact.
- **Node roles** include `NetworkGear` for hosts serving controller/switch/AP
  protocols (CAPWAP, PAPI, Smart Install, TACACS+) and for observed management
  IPs/MACs matched to adopted devices in an imported UniFi inventory. Imported
  matches are retained and show the controller's device name and model;
  controller-only devices are not synthesized onto the traffic map. Clicking a
  node also shows its observed **MAC** and decoded **vendor** when captured (a host's own NIC;
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
./bin/salient map \
  --snapshot salient-data/snapshots/<timestamp>.json.gz \
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
- `--format graphml`: standard GraphML with subnet groups represented as nested
  `<graph>` elements. The output is XML/golden tested; external-app round-trip
  remains a manual release check.

## Importing GraphML into draw.io or yEd (offline)

1. Generate the file: `salient map --snapshot FILE --format graphml --output map.graphml`.
   Output files are created with mode 0600; pass `--output -` only for an
   explicit stdout pipeline.
2. **draw.io** (desktop, offline): File → Import from → Device → select the
   `.graphml` file. Re-layout with Arrange → Layout → Vertical Tree for a
   tiered look, then hand-adjust if needed. Export to `.vsdx` via File → Export
   as → VSDX if Visio is a hard requirement.
3. **yEd** (desktop, offline): File → Open and select the `.graphml`. Use
   Layout → Hierarchical for a tiered view or Layout → Organic for a
   force-directed look. Salient emits standard GraphML, not yEd-specific `y:`
   styling extensions, so styling may need to be applied after import.

Both apps can be used offline, so this path can stay air-gap safe. Confirm the
grouping and layout in the exact installed version before using the result in a
brief; automated tests verify the file structure, not either application's
import behavior.

## Drift-highlighted maps

```sh
salient diff --from older.json.gz --to newer.json.gz --format html --map
```

This writes the HTML drift report and a sibling `.diff.map.html` briefing map.
New nodes and critical edges have green borders, vanished nodes and critical
edges are ghosted, and significant rank changes have amber borders. The
**drift highlights** layer toggle removes these visual overrides without
hiding the underlying terrain.

New hosts, inferred service roles, and service dependencies are investigation
leads for unauthorized or malicious service providers, especially when the
change has no approved operational explanation.

**Provider displacement** tracks client movement between two snapshots for
the same service — "N clients moved from Y to X" — separately from organic
new demand. Only the gaining provider is reported; a provider that only lost
clients isn't flagged on its own. This is descriptive evidence of where
traffic moved, not a judgment about which provider is legitimate.

Vanished nodes and edges come from the older snapshot and remain visual
context only; the newer snapshot stays the authoritative current state.

## Reconciliation-flagged maps

```sh
salient reconcile --snapshot snap.json.gz --assets assets.csv --format html --map
```

This writes the doc-vs-reality report and a sibling `.reconcile.map.html`
briefing map. Observed-but-undocumented hosts get red borders, hosts
contradicting their documented role get amber double borders, and
documented-but-silent assets are ghosted into their subnet group — including
inside hatched blind-spot boxes, where "silent" may just mean "unobserved".
Asset-list VLAN/segment names enrich the subnet-group labels.

Observed-but-undocumented hosts that provide infrastructure or application
services are potential rogue service providers. Role contradictions can also
expose a documented endpoint behaving as an unexpected server. These findings
describe evidence and inventory mismatch, not proven malicious intent.

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
