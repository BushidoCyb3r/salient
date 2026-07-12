# Field map verification worksheet (Phase 0 output)

**Status: VERIFIED against one real grid** (2026-07-11, homelab/production
Security Onion grid, cluster `securityonion`, Elasticsearch 9.3.3, single
sensor `deathstar`). Every default in `internal/escli/fieldmap.go` matched
this grid exactly — zero fieldmap overrides were needed. `salient discover`,
`salient test-connection`, and a real `salient scan --window 24h` all ran
successfully with real results (see below). This validates the defaults for
grids using the standard SO 3.x ECS-mapped Zeek pipeline; a different SO
version or a customized pipeline could still differ — re-run `discover`
against any new grid before trusting it blind.

## Verified mappings

| Concept | Assumed field | Verified field | SO version | Checked |
|---|---|---|---|---|
| Index pattern | `logs-*` | `logs-*` (120 indices/44 data streams) | ES 9.3.3 | ☑ |
| Timestamp | `@timestamp` | `@timestamp` | ES 9.3.3 | ☑ |
| Dataset selector | `event.dataset` | `event.dataset` | ES 9.3.3 | ☑ |
| Sensor | `observer.name` | `observer.name` (one sensor: `deathstar`) | ES 9.3.3 | ☑ |
| Originator IP | `source.ip` | `source.ip` | ES 9.3.3 | ☑ |
| Responder IP | `destination.ip` | `destination.ip` | ES 9.3.3 | ☑ |
| Responder port | `destination.port` | `destination.port` | ES 9.3.3 | ☑ |
| Service | `network.protocol` | `network.protocol` — real values incl. multi-tag `"quic,ssl"` style strings; `ClassifyEvidence` treats any non-empty non-placeholder string as protocol-confirmed, so this is handled correctly | ES 9.3.3 | ☑ |
| Orig bytes | `source.bytes` | `source.bytes` | ES 9.3.3 | ☑ |
| Resp bytes | `destination.bytes` | `destination.bytes` | ES 9.3.3 | ☑ |
| Orig MAC | `source.mac` | mapped in schema but **0% populated** (0/4,038,914 conn docs) | ES 9.3.3 | ☑ |
| Resp MAC | `destination.mac` | mapped in schema but **0% populated** | ES 9.3.3 | ☑ |
| Conn state | `connection.state` | `connection.state` — real full Zeek vocabulary present: SF, S0, RSTR, OTH, RSTO, S3, S1, SH, RSTRH, SHR, REJ, S2, RSTOS0. **S0 (SYN-only/unanswered) is 1.85M of 3.9M conn docs on this grid — nearly as common as SF** — the port-only exclusion this session built is not a theoretical concern, it removes ~half of all traffic on this real network from scoring. | ES 9.3.3 | ☑ |
| DHCP server | `server.address` | `server.address` — populated only on ACK/OFFER records (a REQUEST-only doc has no server field; that absence is itself the confirmation signal). 2,921 `zeek.dhcp` docs/7d on this grid — real production hosts confirmed correctly inferred as `DHCPServer` in a live 7-day scan. | ES 9.3.3 | ☑ |
| DHCP client | `client.address` | `client.address` | ES 9.3.3 | ☑ |
| DHCP assigned IP | `dhcp.assigned_ip` | `dhcp.assigned_ip` — the leased IP, used as the join key to `graph.Node.IP` | ES 9.3.3 | ☑ |
| DHCP hostname | `dhcp.host_name` | `dhcp.host_name` — field exists and is aggregatable, but **empty on every real lease observed this session** (no client in this grid's traffic sent DHCP Option 12). Code correctly handles this (no hostname enrichment fires, no error) — re-test on a grid with more Windows/managed clients, which populate this more often. | ES 9.3.3 | ☑ |
| DHCP host MAC | `host.mac` | `host.mac` — populated. **This is the only working MAC source on this grid** (conn-log `source.mac`/`destination.mac` are 0% populated, see above) — 27 hosts gained a MAC/vendor in a single real 24h scan via this field alone. | ES 9.3.3 | ☑ |
| DHCP lease time | `dhcp.lease_time` | `dhcp.lease_time` — exists, not yet consumed by any query (field-mapped for future use) | ES 9.3.3 | ☑ |

The responder MAC drives two features: L2 gateway detection and per-node
vendor identification. **On this grid both are unavailable** — confirmed via
`discover`'s L2/MAC field-presence probe (0.0% populated on real conn docs,
not just absent from the schema). Gateway inference falls back to the
cross-subnet heuristic; maps label gateways "inferred". This degrades
gracefully as designed, no error, but is a real, confirmed limitation on
this grid, not a hypothetical one.

## Dataset values observed (`discover` output, 2026-07-11)

Datasets use the `zeek.<name>` prefix on this grid (the `zeek.*` candidate,
not the bare name, in every `DatasetCandidates` list already matched
correctly with zero fieldmap edits needed).

| Log type | Candidates | Found on grid |
|---|---|---|
| conn | `conn`, `zeek.conn` | **`zeek.conn`** (4,038,915 docs/7d) |
| dns | `dns`, `zeek.dns` | **`zeek.dns`** (5,408,345 docs/7d) |
| kerberos | `kerberos`, `zeek.kerberos` | **NOT FOUND** — dataset absent entirely on this grid |
| smb | `smb_mapping`, `smb_files`, … | **NOT FOUND** — dataset absent entirely on this grid |
| ssl | `ssl`, `zeek.ssl` | **`zeek.ssl`** (425,558 docs/7d) |
| http | `http`, `zeek.http` | **`zeek.http`** (232,684 docs/7d) |
| dhcp | `dhcp`, `zeek.dhcp` | **`zeek.dhcp`** (2,921 docs/7d — low volume but present) |
| ldap | `ldap`, `zeek.ldap` | **NOT FOUND** — dataset absent entirely on this grid |

Other datasets present but not currently consumed by Salient (candidates for
future Phase 5 work): `zeek.x509` (1,434 docs — TLS cert identity),
`zeek.ssh` (580 docs), `zeek.software`, `zeek.notice` (787 docs — Zeek's own
built-in detections, including scan detection), `zeek.weird`,
`zeek.ja4d`/`zeek.ja4ssh` (JA4 fingerprinting).

## Phase 0 decision points — ANSWERED

- **L2/MAC fields survive ECS?** **No** — mapped in the schema but 0%
  populated on real conn documents. Gateway inference on this grid always
  uses the heuristic fallback, never the primary MAC-convergence method.
- **kerberos/smb/dns datasets populated?** **Partially** — DNS is heavily
  populated (5.4M docs/7d) and DNS role inference works correctly (see
  below). Kerberos, SMB, and LDAP datasets are **entirely absent** on this
  grid, meaning `RoleDC` and `RoleFileServer` inference will never fire here
  — not a bug, this grid's Zeek deployment doesn't log those protocols (or
  no matching traffic exists). A grid that does enable them would need
  re-verification of those two roles specifically.
- **Edge agg timing:** a real `salient scan --window 24h` (not the full 14d
  target) against this grid: **73,888 edges aggregated, 3,729 nodes scored,
  9.5 seconds wall time.** Well within the <60s target for a 24h window;
  strongly suggests the 14-day target is achievable but wasn't directly
  measured (a full 14-day scan against a live production grid wasn't run,
  to avoid unnecessary load — re-test with `--window 336h` if a hard number
  is needed before a release claim).

## Real-scan sanity check (role inference + terrain ranking)

The 24h scan's top-5 terrain output:

```
1. 10.18.61.1       DNSServer          composite 0.77
2. 10.10.40.1       DNSServer          composite 0.66
3. 172.16.10.1      DNSServer          composite 0.54
4. 8.8.8.8          DNSServer          composite 0.39
5. 10.18.61.2       Unknown            composite 0.38
```

Three internal `.1`-address hosts (plausible per-subnet resolvers/gateways)
plus Google Public DNS (8.8.8.8) all correctly inferred as `DNSServer` and
ranked at the top — a strong positive signal for both role inference and
terrain ranking against real traffic, though not a rigorously
ground-truthed confirmation (no independent asset inventory was reconciled
against this scan in this session).

Service-evidence mix from the same scan: **5,346 protocol-confirmed, 228
responder-confirmed, 68,314 port-only** — 92.5% of all edges observed in
this 24h window were port-only (scan/unanswered) traffic, all correctly
excluded from scoring and role inference. This is the single strongest
real-world validation available for the service-evidence-tiers work: on a
real network, the majority of raw connection attempts are noise, and the
feature this session built specifically to filter that noise out is doing
real, substantial work — not a theoretical improvement.

## Overriding without a rebuild

```yaml
# custom-fieldmap.yaml — only set what differs from defaults
index_pattern: "so-zeek-*"
source_mac: "zeek.conn.orig_l2_addr"
datasets:
  conn: ["zeek.conn"]
```

```sh
salient discover --fieldmap custom-fieldmap.yaml
```
