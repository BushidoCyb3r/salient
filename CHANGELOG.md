# Changelog

All notable changes to Defilade are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Topology layout — declared routing** (the *tiered* layout, renamed
  *topology* and extended): the realistic tiered map now also draws the
  operator-declared device hierarchy. Tag a device's network layer (its `Type`:
  boundary/router/switch) and assign it the IP **ranges it owns**; it collapses
  to one focus node — regardless of how many IPs/VLANs it spans — placed in a
  boundary/router/switch band between the external box and the VLAN rows, and
  every VLAN whose range it owns threads up through it. The routing hops draw
  **dashed** — declared, never observed — keeping the honesty rule (flow data
  can't see L2 fabric, so you co-author it). Layer order (switch → router →
  boundary) supplies the tiering; no manual uplinks. Foundation for
  scan-to-validate: declared-vs-observed deviations stand out. New
  `Device.OwnsCIDRs` field + `SetDeviceOwns` binding, persisted in the registry.
- **Manual asset entry for reconcile**: alongside "Load asset CSV…", an **Enter
  manually…** button opens an in-app grid with the columns pre-loaded (IP,
  hostname, role, VLAN/segment). Type the asset list directly — blank rows are
  ignored, only IP is required — and it reconciles through the exact same
  parse/compare path as a CSV file. No spreadsheet needed for a handful of hosts.
- **Operator-declared segments**: a **Segments** panel to override the naive
  auto-`/24` grouping with the real subnet layout. Declare CIDRs (with optional
  names) — e.g. split a `/24` into two `/25`s, or merge several `/24`s into one
  supernet box — and each host falls into the most-specific segment containing
  it; anything undeclared still groups by `/24`. Persisted in the device
  registry and applied to every view (overview, drill-in, gateways, edges).
- **Uniform grid layout** for the segment overview (new default, alongside
  *organic* and *tiered*): each VLAN box is one cell of a grid with its hosts in
  a fixed mini-grid, so boxes come out the same size and orderly instead of the
  force sim ballooning and scattering them.
- **Realistic tiered layout**: the *tiered* view now reads like a network
  diagram — the external/internet box spans the top, VLAN boxes sit in a row
  below, and inside every box the router (gateway) is pinned to the top with
  hosts stacked beneath it (core → service → client). The chosen layout now
  persists across re-renders, so the ordering holds when drilling into a VLAN.
- **Segment-flow map** is the new default for large grids: every real internal
  VLAN gets its own box (never lumped into "other internal networks"), each
  showing its own top hosts plus an "N more hosts" chip. The default flow view
  is a high-level **segment→segment backbone** (one aggregated line per VLAN
  pair, colored by dominant service class and sized by volume) — logical flow at
  a glance instead of an N² host-level mesh. **Click a host** to light its own
  connections, **click a VLAN box** to light everything that segment talks to,
  **double-click a VLAN** to drill into its full detail (then "← overview"), and
  **show all flows** draws the full mesh. Overview defaults to the
  tiered/directional layout. Replaces the old global top-20 + group-cap
  condensation, which lumped lightly-populated real segments together and let a
  busy VLAN starve the rest.
- **Show every private host (dense)** map toggle — an escape hatch that promotes
  every RFC1918 host to its own node instead of collapsing low-ranked ones into
  aggregates, while external peers still condense. Every connection between the visible hosts is drawn
  (the edge budget is bypassed in this explicit "show everything" mode), and
  every private VLAN keeps its own group box (no group cap, so a real segment is
  never lumped into "other internal networks"). Capped at 1500 promoted hosts
  (`config.MapAllPrivateCap`) with a finding when the cap clips, so large grids
  stay renderable. Persisted in the device registry.
- **Pin to map / Unpin from map**: force a specific host to always render as its
  own overview node regardless of rank, from the map or a host-list row. Pinned
  nodes get an amber border; pins persist in the device registry.
- **Per-group AI tagging**: **Suggest tags for listed hosts** tags only the
  currently-filtered hosts of an aggregate (capped at 100 per run, sidecar-merged
  so targeted runs accumulate).
- **Per-node MAC and OUI vendor**: scans capture each host's responder MAC
  (gateway MACs excluded so a router's MAC is never mis-attributed) and decode
  the vendor from a curated OUI table. Surfaced in node evidence, the host list,
  same-device hints, and the AI payload.
- **Network-vendor protocol recognition**: UniFi, Cisco, Aruba, Meraki, and
  Juniper protocols added to the port table (~90 → ~110 recognized services).
- **NetworkGear role**: hosts serving controller/switch/AP-only protocols
  (CAPWAP, PAPI, Smart Install, TACACS+) are typed as network gear and promoted
  to the core tier.
- **Host-list row actions**: right-click an aggregated host to assign it to a
  device, set its role, or pin it — the same actions available on map nodes.
- **L2/MAC coverage reporting** at connect, so observed-vs-inferred gateway
  evidence is visible.

### Changed
- Refocused on key-terrain identification: ranked terrain is the primary console
  surface, map nodes are sized and colored by criticality, the terrain report
  leads with a Top 10 and score-driver rationale, and the topology device-diagram
  layout is demoted to an optional secondary view.
- Aggregate "N other hosts" drill-in list now shows each host's MAC and vendor
  and is filterable by them.
- Overview grouping no longer coarsens subnets past the operator's true prefix;
  overflow groups collapse into an honest "other internal networks" bucket.

### Fixed
- **Drilling into a VLAN now shows every host** instead of still collapsing
  low-value clients into an "N workstations" aggregate — the detailed build
  honors the "show everything" intent, so drill-in is true full detail and the
  **show every private host** toggle expands hosts in every view (previously it
  only affected the overview). Fixes the aggregate that listed zero hosts on
  click in the drilled-in view.
- Cross-VLAN dependency edges were dropped from condensed overviews when the
  element budget was tight; they are now protected, and confusing inferred-gateway
  diamonds are de-cluttered.
- `refreshDevices` dropped the pin set from the in-memory registry, which could
  leave the pin/unpin menu label stale.

[Unreleased]: https://github.com/BushidoCyb3r/defilade/commits/feature/desktop-map-viewer
