# Field map verification worksheet (Phase 0 output)

**Status: UNVERIFIED.** Every value in `internal/escli/fieldmap.go` is an assumption.
Run `salient discover` and `salient test-connection` against the homelab grid,
record ground truth here, then update the default `FieldMap` and delete the
`// UNVERIFIED` markers. The query code (Phases 1–4) is implemented against these
assumed names; wrong names fail loudly (`ErrZeroBuckets`) rather than silently, so
a scan is only trustworthy once this table is filled in and the defaults match.

## Verified mappings

| Concept | Assumed field | Verified field | SO version | Checked |
|---|---|---|---|---|
| Index pattern | `logs-*` | | | ☐ |
| Timestamp | `@timestamp` | | | ☐ |
| Dataset selector | `event.dataset` | | | ☐ |
| Sensor | `observer.name` | | | ☐ |
| Originator IP | `source.ip` | | | ☐ |
| Responder IP | `destination.ip` | | | ☐ |
| Responder port | `destination.port` | | | ☐ |
| Service | `network.protocol` | | | ☐ |
| Orig bytes | `source.bytes` | | | ☐ |
| Resp bytes | `destination.bytes` | | | ☐ |
| Orig MAC | `source.mac` | | | ☐ |
| Resp MAC | `destination.mac` | | | ☐ |

The responder MAC drives two features: L2 gateway detection (a MAC answering
for many IPs = that segment's router) and per-node vendor identification (OUI
lookup on each host's own MAC). Both degrade gracefully — absent MAC fields
just mean inferred gateways and no vendor labels, never an error — but verify
`destination.mac` against a real grid to enable them.

## Dataset values observed (`discover` output)

| Log type | Candidates | Found on grid |
|---|---|---|
| conn | `conn`, `zeek.conn` | |
| dns | `dns`, `zeek.dns` | |
| kerberos | `kerberos`, `zeek.kerberos` | |
| smb | `smb_mapping`, `smb_files`, … | |
| ssl | `ssl`, `zeek.ssl` | |
| http | `http`, `zeek.http` | |
| dhcp | `dhcp`, `zeek.dhcp` | |
| ldap | `ldap`, `zeek.ldap` | |

## Phase 0 decision points

- **L2/MAC fields survive ECS?** yes / no → decides gateway inference primary vs fallback (§8.4). Answer: ______
- **kerberos/smb/dns datasets populated?** yes / no → conn-only grid degrades role inference to port guessing. Answer: ______
- **Edge agg timing:** composite agg over 14d window, hand-run in Kibana Dev Tools then from Go. Target <60s. Measured: ______

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
