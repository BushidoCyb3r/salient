# Device config ingestion

Salient can diff the network you *declared* — the router and firewall configs
you actually run — against the network it *observed* in a snapshot. It reports
declared gateways, subnets that are documented but silent, subnets that are
observed but undeclared, and firewall rules that are contradicted by real
traffic (denied-but-observed) or never exercised (unused permits).

## Ground rules

- **Upload only.** Salient never logs into your controllers or routers and
  never pulls config live. You export the config yourself and hand Salient the
  file(s).
- **Secrets are stripped at parse time.** Enable secrets, SNMP communities,
  TACACS/RADIUS keys, and pre-shared keys are discarded before anything is
  stored. Only the parsed topology and rules are kept.
- **Raw config text is never persisted.** Only the sanitized parsed devices
  (`[]DeclaredDevice`) land in `salient-data/declared.json`. Inventory and
  policy diffs are recomputed against the snapshot whenever it is loaded. The
  original file is read, parsed, and discarded.
- **Terrain classification applies.** The output describes network layout and
  enforcement policy — protect it at the network's classification.

## What to export

### Cisco IOS

Save the running-config as plain text:

```
show running-config
```

Copy the output to a `.txt` / `.cfg` / `.conf` file, one file per device.
Salient autodetects IOS by its `hostname` / `interface` / `access-list` lines.

Parsed: interfaces and their prefixes/VLANs/ACL bindings (including L2
switchport access VLANs and trunk-mode flags), DHCP pools, static routes, VLAN
names, and extended/standard access-lists. NAT, VRF, IPv6, and
reachability simulation are out of scope (declared rules are matched against
observed flows only).

### UniFi (both controller stacks)

UniFi keeps network config in the controller's REST API as JSON. Export the
three collections below and hand Salient all of them together — they fold into
one declared controller.

**UniFi OS** (UDM / UDM-Pro / Cloud Key Gen2+, `/proxy/network` prefix):

```
curl -k -b <cookie> https://<controller>/proxy/network/api/s/default/rest/networkconf   > unifi-networkconf.json
curl -k -b <cookie> https://<controller>/proxy/network/api/s/default/rest/firewallrule  > unifi-firewallrule.json
curl -k -b <cookie> https://<controller>/proxy/network/api/s/default/stat/device        > unifi-device.json
```

**Legacy controller** (self-hosted / older Cloud Key, port 8443, no proxy
prefix):

```
curl -k -b <cookie> https://<controller>:8443/api/s/default/rest/networkconf   > unifi-networkconf.json
curl -k -b <cookie> https://<controller>:8443/api/s/default/rest/firewallrule  > unifi-firewallrule.json
curl -k -b <cookie> https://<controller>:8443/api/s/default/stat/device        > unifi-device.json
```

Replace `default` with your site name if you renamed it. `<cookie>` is the
authenticated session cookie from your browser or a login `POST` to
`/api/login` (UniFi OS: `/api/auth/login`).

**Browser method (no curl):** log into the controller, then open each of the
three URLs above in a new tab and use *Save Page As → JSON*. Same three files.

Salient autodetects UniFi JSON (a top-level array, or an object with a `data`
key). VLANs/networks give it subnets; `firewallrule` gives it the rules;
`stat/device` matches declared interfaces to observed MACs.

## Using it

### GUI

Open a snapshot, then in the **Data** tab → **Device Configs** →
*Load device configs…*. Select one or more exported files (Cisco text and
UniFi JSON can be mixed in one selection). The map stamps declared gateway
identity onto the inferred gateways, and the task log lists the diff findings.
The ingest persists, so it reapplies automatically when you reload the
snapshot, and feeds the Hunt view's declared-policy leads. Clear it with the
`×` on the chip.

### CLI

```
salient declared --snapshot SNAP.json.gz --configs ios-router.cfg,unifi-networkconf.json,unifi-firewallrule.json,unifi-device.json
```

Prints `{ "inventory": …, "policy": … }` JSON on stdout: `inventory` is the
declared-vs-observed reconciliation (declared gateways, silent subnets,
undeclared CIDRs), `policy` is the firewall reconciliation (denied-but-observed
violations, unused permits, and a count of rules skipped because they couldn't
be honestly evaluated from flow data). Comma-separate multiple files; UniFi
JSON exports are grouped into one controller automatically.
