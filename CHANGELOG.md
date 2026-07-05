# Changelog

All notable changes to Defilade are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- Aggregate "N other hosts" drill-in list now shows each host's MAC and vendor
  and is filterable by them.
- Overview grouping no longer coarsens subnets past the operator's true prefix;
  overflow groups collapse into an honest "other internal networks" bucket.

### Fixed
- Cross-VLAN dependency edges were dropped from condensed overviews when the
  element budget was tight; they are now protected, and confusing inferred-gateway
  diamonds are de-cluttered.
- `refreshDevices` dropped the pin set from the in-memory registry, which could
  leave the pin/unpin menu label stale.

[Unreleased]: https://github.com/BushidoCyb3r/defilade/commits/feature/desktop-map-viewer
