# Salient

![Salient](docs/salient-logo.png)

**A common operational picture (COP) for the network domain — built passively, from telemetry the grid already has.**

Salient connects read-only to Elasticsearch, aggregates existing Zeek telemetry,
and turns observed traffic into a scored dependency graph and ranked
Mission Relevant Terrain-Cyber (MRT-C) report: what's out there, what depends
on what, and which terrain matters most to the mission — with the evidence
behind every ranking. It is built for hunting teams new to an environment who
need a COP of that terrain and its dependencies fast, without active scanning
or any change to the Security Onion deployment they're operating on.

The same evidence can identify potential rogue or malicious service providers:
Salient infers the services hosts actually provide, flags systems and roles
that contradict the asset inventory, and highlights newly appeared hosts,
roles, and service dependencies across snapshots. These are investigation
leads backed by observed behavior, not automatic declarations of malicious
intent.

Dropped into an unfamiliar network, a hunt team's biggest cost is time: figuring
out what actually matters before an active scan tips off an adversary or trips
something fragile. Salient mines telemetry the grid already has and ranks what
to defend or investigate first, with the evidence behind each rank instead of
a guess.

The map is a criticality view of that observed dependency terrain, not a network
diagram. Node size and heat emphasize the systems whose compromise or loss would
matter most. The declared-device topology layout remains available as an optional
cross-check; it is not the product's primary view.

The desktop console is the primary interface. It connects to the grid, runs scans
with live progress, browses saved snapshots, investigates role evidence, and
exports maps from one native window on Linux, macOS, or Windows.

Release history is tracked in [CHANGELOG.md](CHANGELOG.md).

## Operator console

The console provides:

- Elasticsearch connection with API key, CA certificate, custom field map, and
  explicit insecure-TLS controls.
- Automatic grid discovery at connect: observed datasets, missing-dataset
  warnings (conn is required), and sensors, in the task log.
- Configurable scan window, scope CIDRs, and timezone.
- Live scan progress and cancellation.
- A Key Terrain drawer leading with the ranked systems and their score-driver evidence.
- Criticality maps grouped by subnet, sized and heated by terrain score, with
  observed or inferred gateways.
- Grid and organic layouts, plus an optional declared-device topology cross-check.
- Snapshot browsing and offline map reconstruction.
- Aggregate drill-in: clicking an "N other hosts" node opens a filterable list
  of every collapsed host with its rank, role, services, device, MAC, and
  vendor. Right-click any row to assign it to a device or correct its role, and
  use **Suggest tags for listed hosts** to AI-tag just the filtered set, or
  **Pin to map** to promote a collapsed host to its own node.
- Flow-arrow drill-in: clicking a bundled flow arrow whose endpoint is a
  grouped node (for example the external traffic bucket) opens the same
  panel with the real IPs behind that specific arrow.
- Per-host service lists derived from observed responder ports (~110 recognized
  services): the full Active Directory protocol set plus network-vendor
  protocols for UniFi, Cisco, Aruba, Meraki, and Juniper gear.
- Network-gear detection: hosts serving controller/switch/AP-only protocols
  (CAPWAP, Aruba PAPI, Cisco Smart Install, TACACS+) are typed as NetworkGear
  and promoted to the core tier.
- Per-node MAC and OUI vendor: each host shows its observed responder MAC and
  the vendor decoded from it (gateway MACs are excluded so a router's MAC is
  never mis-attributed to the hosts behind it). Shared-MAC same-device hints
  complement the hostname-based ones.
- Device identity: link multiple IPs (for example one router across several
  VLANs) into one named device with type and notes; linked nodes get a shared
  badge and a device card. Hostname- and MAC-based same-device hints suggest
  links; the operator confirms or dismisses.
- Role correction: right-click **Set role…** overrides a wrong inference with
  any text; the correction is marked ✎, the original inference stays visible,
  and known roles also move the node to the correct map tier.
- Drift comparison: pick any older snapshot as a baseline and see what
  appeared, vanished, changed role or rank, or began providing new service
  dependencies — including new DNS/DHCP/auth/file/database providers at any
  terrain rank, not just newcomers to the top. Edges carry a service-evidence
  level (protocol-confirmed, responder-confirmed, or port-only); port-only
  connection attempts never influence rankings or roles.
- Asset reconciliation: load an inventory CSV and see undocumented hosts,
  documented-but-silent assets, and role contradictions flagged on the map,
  exposing potential rogue service providers for investigation.
- Service Authority view: one row per sensitive-service provider, sorted by
  client count, each with a dossier of role, evidence, and first/last seen.
- Hunt Leads: auto-prioritized investigation queue — undocumented hosts,
  contradicted roles, new or displaced service providers — each with the
  evidence behind it and a one-click copy of the matching Hunt query;
  approve a lead to suppress it as an expected/benign provider going forward.
- Optional model-assisted device tags based on observed network communication,
  grounded in operator-confirmed device names, roles, and labels; suggestions
  can be accepted into durable labels or dismissed permanently.
- Search by IP, hostname, role, service, device name, or label.
- Node evidence and right-click actions for copying, focusing, assigning to a
  device, and correcting roles.
- PNG export of the exact on-screen layout, plus self-contained HTML and GraphML.

Elasticsearch and model API keys remain in memory and are never written to
disk. Operator annotations (devices, labels, role overrides) persist in
`salient-data/devices.json` and survive rescans.

## Key-terrain scoring

Salient ranks key terrain from observed dependency traffic, not labels or icon
size. Each rank is a composite score:

- **40% critical-service dependents:** distinct hosts depending on this node for
  auth, DNS/name resolution, file, or database services.
- **25% PageRank:** dependency centrality in the weighted traffic graph; auth
  and DNS/name-resolution edges count 3×.
- **20% betweenness:** chokepoint value — how often dependency paths pass
  through the node.
- **15% subnet spread:** how many client subnets depend on the node.

Scores are min-max normalized within the snapshot and ranked descending; invalid
terrain artifacts such as multicast, broadcast, loopback, and link-local
addresses are excluded from the composite. The console's **Key Terrain** button
shows the top ranked visible hosts/devices and opens a drawer that can zoom to
the selected node. Collapsed device nodes inherit their strongest member rank.

## Install and run

### Release downloads

Download the latest build from
[GitHub Releases](https://github.com/BushidoCyb3r/salient/releases/latest).
Assets labeled or named `salient-cli-*` are the standalone command-line tool;
the `.deb`, `.rpm`, `Salient-macOS.zip`, and `Salient-Windows.exe` assets are
the desktop console. Each release includes `SHA256SUMS` and build-provenance
attestations.

The desktop console does not accept a UniFi controller address or API key. Use
the standalone CLI's `unifi-export` command to create four local JSON files,
then open a snapshot in the desktop console and import all four through
**Data → Device Configs → Load device configs…**. See the
[complete UniFi CLI-to-GUI workflow](docs/config-ingest.md#unifi).
Adopted gateways, switches, and access points whose management IP or MAC
matches an observed snapshot node are retained and named on the map as
`NetworkGear`; controller-only devices are reported but not fabricated as
traffic nodes.

The CLI is a static binary. On Linux or macOS, make the downloaded CLI executable
before its first run:

~~~sh
chmod +x <downloaded-cli>
./<downloaded-cli> --help
~~~

Linux desktop packages install their webview dependency through the package
manager. macOS and Windows builds are unsigned; verify the downloaded file
against `SHA256SUMS` before accepting the platform warning. See
[docs/GUI.md](docs/GUI.md) for platform-specific installation and runtime notes.

### Build from source

Prerequisites:

- Git
- Make
- Go 1.26.5 or newer
- Node.js and npm

Linux also needs the native webview development packages:

~~~sh
# Debian/Ubuntu
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev

# Fedora/RHEL/Rocky
sudo dnf install webkit2gtk4.1-devel gtk3-devel
~~~

Clone, download the pinned dependencies, and build:

~~~sh
git clone https://github.com/BushidoCyb3r/salient.git
cd salient
make gui-deps
make gui
make build
~~~

Launch the resulting application:

~~~sh
# Linux
./gui/build/bin/salient

# macOS
open gui/build/bin/Salient.app

# Windows PowerShell
.\gui\build\bin\salient.exe
~~~

## First connection

1. Create a read-only Elasticsearch API key. In Kibana, go to **Stack
   Management → Security → API keys → Create API key**, name it, toggle
   **Control security privileges** on, and replace the editor contents with:

   ```json
   {
     "salient_ro": {
       "cluster": ["monitor"],
       "indices": [
         {
           "names": ["logs-*"],
           "privileges": ["read", "view_index_metadata"]
         }
       ]
     }
   }
   ```

   The `cluster: ["monitor"]` privilege is required — Salient calls the
   Elasticsearch root `info` API at connect, and without it the grid returns
   `action [cluster:monitor/main] is unauthorized ... HTTP 403`. Create the key,
   then copy its **Base64 ("encoded")** value for the connect form. Full steps
   (firewall, TLS, Dev Tools alternative) are in
   [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
2. Launch the console and enter the manager URL, API key, and CA certificate.
3. Set the analysis window, timezone, and optional scope CIDRs.
4. Connect. The task log immediately shows what the grid holds: observed
   datasets with counts, warnings for missing ones (conn is required), and
   sensors — verify coverage before spending a scan window.
5. Select **Run Scan**.
6. Select the completed snapshot to inspect and export its map.
7. Optionally configure **AI Device Tagging** and select **Suggest Tags** to add
   communication-based labels to visible devices.

The default field map was verified against one Security Onion 3.x / Elasticsearch
9.3.3 grid. Zeek-to-ECS mappings can still vary by release and deployment, so run
`test-connection` and `discover` against every target grid before trusting scan
output. The verified values and known coverage limits are recorded in
[docs/FIELDMAP.md](docs/FIELDMAP.md).

## What a scan produces

Salient performs server-side Elasticsearch aggregations rather than downloading
raw events. A completed scan writes:

- A compressed snapshot containing scored nodes, dependencies, evidence, and
  observation metadata.
- A detailed analyst report.
- A self-contained interactive briefing map.
- An optional protected `.tags.json` sidecar containing validated model
  suggestions when device tagging is used.

Artifacts are stored under salient-data/snapshots, salient-data/reports, and
salient-data/maps. The console can reopen snapshots without reconnecting to the
grid.

Large unfocused maps are condensed into a **segment-flow overview**: every real
VLAN gets its own box showing its top hosts (the rest behind an "N more hosts"
chip), with dependencies bundled between segments. This is intentional, not a
complete-topology view. **Click a VLAN box (▸) to drill into a full-detail view
of that segment**, then "← overview" to return; clicking an "N more hosts" chip
opens the full host list behind it. See [docs/MAPS.md](docs/MAPS.md) for the
full model.

## Console workflows

### Inspecting hosts

Click any node for its evidence: role (with the operator correction and the
original inference when overridden), rank, composite score, device, labels,
observed services, MAC and vendor, and the raw evidence strings behind each
role. Click an aggregate "N other hosts" node to open the host-list panel —
type to filter by IP, hostname, role, service, device, MAC, or vendor; click a
row for its evidence, or right-click it to assign a device or set a role.
Aggregated hosts are full participants: **Suggest tags for listed hosts** runs
AI tagging over the currently-filtered set (up to 100 at a time), and
right-click **Pin to map** promotes any collapsed host to its own node.

### Showing every private host

Condensed maps keep only top-ranked hosts. The **show every private host
(dense)** checkbox in the View tab instead promotes every RFC1918 (private)
host to its own node while external peers still collapse into one box — a
fuller, more accurate picture on grids with a manageable internal host count. A cap
(`config.MapAllPrivateCap`, 1500) bounds it: past that, the highest-ranked
private hosts are shown and the rest re-aggregate, with a finding noting the
count so a very large grid can't produce an unrenderable map. The setting
persists in the device registry.

### Pinning a host onto the map

Condensed briefing maps keep only the top-ranked hosts and collapse the rest
into "N other hosts" aggregates. To force a specific host to always show as its
own node — a low-traffic but important box you want to watch — right-click it
(on the map or in a host-list row) → **Pin to map**. Pinned nodes get an amber
border and are retained additively (they show even if that pushes the map past
its element target). **Unpin from map** returns the host to its aggregate. Pins
persist in the device registry.

### Linking IPs into devices

A router with an interface per VLAN appears as several unrelated nodes. To
merge their identity: right-click the first IP → **Assign to device…** → type a
name and press Enter. Right-click the remaining IPs → **Assign to device…** →
pick the existing name. Linked nodes get a violet badge and the device name in
their label. The **Devices** sidebar section lists every device; click one for
its card — editable notes, member IPs (click to zoom, unlink to remove), and
delete. When the same hostname is observed on two or more IPs the Devices
section offers a one-click "same device?" hint; dismissals are remembered.

### Correcting a wrong role

Right-click the node → **Set role…** → type anything (`Camera`, `PLC`,
`Octoprint`) or pick a suggestion; Enter applies, an empty value clears. The
evidence panel shows `role: ✎ Camera (operator)` with the original inference
kept underneath — corrections never destroy observed evidence. Known role
names also move the node into the right map tier (core/service/client).

### Comparing snapshots (drift)

Load the snapshot under review, pick an older snapshot in the **Drift**
baseline dropdown, and select **Compare**. Green borders are new hosts, ghosted
dashed nodes vanished, amber rank changes; new and vanished edges recolor the
same way. The change counts print in the task log. **Clear** (or loading
another snapshot) returns to the normal view.

A newly appeared host, inferred service role, or dependency can indicate an
unauthorized service provider. Drift supplies the behavioral evidence and time
boundary; the operator determines whether the change is expected or malicious.

### Reconciling an asset inventory

Select **Load asset CSV…** in the **Reconcile** section and pick your
inventory export. The map flags observed-but-undocumented hosts (red),
documented-but-silent assets (ghosted — check sensor blind spots before
calling them decommissioned), and role contradictions (amber double border).
Segment names from the CSV label the subnet boxes. The CSV stays applied
across snapshot switches until cleared with **×**.

An undocumented host providing DNS, authentication, web, database, file, or
network-infrastructure services is a potential rogue or malicious service
provider. Reconciliation identifies that mismatch; it does not assign intent
without analyst validation.

The CSV format is forgiving — real spreadsheet exports work as-is. Only an IP
column is required; headers are autodetected by keyword:

| Column   | Recognized header keywords                                  |
|----------|-------------------------------------------------------------|
| IP       | `ip`, `ipaddress`, `ipaddr`, `ipv4`, `ipv6`, or `address`   |
| Hostname | `host`, `name`, `fqdn`, `asset`, `system`, `device`         |
| Role     | `role`, `function`, `type`, `purpose`, `service`, `description` |
| Segment  | `vlan`, `segment`, `subnet`, `site`, `enclave`, `zone`, `network` |

~~~csv
ip,hostname,role,segment
192.168.20.1,udm,Gateway,vlan20
10.10.40.5,nas01,FileServer,storage
~~~

Column order does not matter, extra columns are ignored, rows without a
parseable IP are skipped with a logged warning, and a headerless file still
works (the IP column is detected by content).

## Command line

The CLI supports the complete scan and offline-analysis workflow. Examples below
assume the release binary is available as `salient`; source builds use
`./bin/salient` instead.

~~~sh
export SALIENT_ES_URL="https://so-manager:9200"
export SALIENT_API_KEY="<base64 id:key>"

salient test-connection --ca-cert grid-ca.pem
salient discover --ca-cert grid-ca.pem --window 168h
salient scan --ca-cert grid-ca.pem --window 336h \
    --scope 10.0.0.0/8 --tz America/New_York
salient list
salient view
~~~

| Command | Purpose |
|---|---|
| `test-connection` | Verify authentication, read-only privileges, index discovery, and core field mappings. |
| `discover` | List datasets, sensors, and L2/MAC coverage for a target grid. |
| `scan` | Aggregate a window and write a snapshot, analyst report, and briefing map. |
| `list` / `view` | List stored snapshots or open the local report/map index. |
| `report` | Re-render a snapshot as HTML, JSON, or GraphML. |
| `map` | Render a snapshot as interactive HTML, SVG, or GraphML. |
| `diff` | Compare two snapshots and optionally render a drift-highlighted map. |
| `reconcile` | Compare a snapshot with an asset CSV and optionally render the findings. |
| `declared` | Compare exported Cisco IOS/UniFi configs with observed inventory and policy. |
| `unifi-export` | Export import-ready config JSON through the local Network Integration API. |
| `mission` | Score dependency proximity to operator-selected mission systems. |
| `stability` | Report terrain-rank stability across at least three stored snapshots. |
| `analyze` | Explicitly send a capped snapshot summary to a configured model endpoint. |
| `completion` | Generate shell-completion scripts. |

Common CLI operations:

~~~sh
salient report --snapshot SNAP.json.gz --format json --output report.json
salient map --snapshot SNAP.json.gz --format graphml --output map.graphml
salient diff --from OLD.json.gz --to NEW.json.gz --map
salient reconcile --snapshot SNAP.json.gz --assets assets.csv --map
# Set SALIENT_UNIFI_API_KEY without echo/history as shown in docs/config-ingest.md.
salient unifi-export --controller https://192.168.1.1
salient declared --snapshot SNAP.json.gz \
  --configs router.cfg,salient-data/unifi-export/unifi-integration-networks.json,salient-data/unifi-export/unifi-integration-devices.json,salient-data/unifi-export/unifi-integration-firewall-zones.json,salient-data/unifi-export/unifi-integration-firewall-policies.json
unset SALIENT_UNIFI_API_KEY
salient mission --snapshot SNAP.json.gz --scope 10.0.1.10,10.0.1.11
salient stability --data-dir salient-data --format json
~~~

`analyze` is the only CLI operation that can send network-derived data anywhere
other than Elasticsearch. Loopback endpoints work without an egress flag;
remote endpoints require HTTPS and `--allow-network-data-egress`. Supply the
endpoint credential through `SALIENT_AI_API_KEY`, never a command-line flag:

~~~sh
export SALIENT_AI_API_KEY='<endpoint credential>'
salient analyze --snapshot SNAP.json.gz \
  --endpoint https://approved.example/v1/chat/completions \
  --model approved-model --allow-network-data-egress
~~~

Run `salient COMMAND --help` for every flag. See [docs/MAPS.md](docs/MAPS.md)
for export interpretation and [docs/config-ingest.md](docs/config-ingest.md)
for supported device-config exports.

## Security model

- Elasticsearch access is read-only. Salient does not change grid
  configuration, indices, or documents.
- The console writes only local snapshots, reports, maps, operator registries,
  sanitized declared models, tag sidecars, and operator-selected exports.
- Runtime assets are bundled locally. There are no CDN dependencies or telemetry.
- The CLI is a static binary. The desktop console uses the operating system's
  native webview and must be built per target platform.
- Model requests are snapshot-only and send capped, summarized topology. Remote
  endpoints require HTTPS and an explicit network-data-egress acknowledgement.
- Model API keys stay in memory. Tag sidecars record only endpoint host, model,
  timestamp, and validated suggestions.
- `unifi-export` contacts only the operator-supplied local console, sends the
  Network Integration key in memory, issues GET requests only, and writes
  protected import files.
- On POSIX systems, managed artifacts use 0600 files in 0700 directories.
  Windows exports inherit the destination directory's ACLs.

Terrain artifacts expose network dependencies and critical systems. Protect them
at the classification and handling level of the network they describe.

## Limitations

- **Passive-window blindness:** only systems that communicated during the selected
  window are visible.
- **Sensor-coverage blindness:** unsensed east-west traffic is absent. Empty
  in-scope networks are possible blind spots, not proof of silence.
- **Logical, not physical topology:** maps show Layer 3 dependencies, not switches,
  cabling, ports, or silent devices.
- **Inferred gateways:** when MAC evidence is unavailable, gateway placement is
  synthesized and displayed as inferred.
- **Evidence-scored roles:** server roles are conservative hypotheses backed by
  observed behavior; uncertain nodes remain Unknown.
- **Model suggestions are not evidence:** generated device tags are displayed
  separately and must be verified by an operator.

## Model-assisted device tagging

The console can suggest device tags from communication patterns in a stored
snapshot. Select an API shape, enter the endpoint and model, provide an API key
when required, and explicitly acknowledge remote network-data egress. The key
is kept only for the in-flight request.

Supported request shapes are OpenAI-compatible chat completions, Anthropic
Messages, and Gemini GenerateContent. These cover the major hosted APIs, local
Llama servers that expose a compatible endpoint, and compatible Ask Sage
routes. GenAI.mil and other tenant-controlled services use the API shape,
endpoint, model, and credentials issued for that environment; Salient does not
assume a universal public endpoint.

Only capped node and edge summaries are sent, never raw Zeek events or
Elasticsearch credentials. The summaries include inferred roles, named services
per observed responder port, and each host's MAC and decoded vendor (snapshots
created before the expanded port table and MAC capture carry generic `port-N`
names and no vendor — rescan to give the model the richer labels). Tagging runs
either over the whole map (**Suggest Tags**) or over just the hosts listed in an
aggregate panel (**Suggest tags for listed hosts**, capped at 100 per run and
merged into the sidecar so targeted runs accumulate). Operator-confirmed facts —
device names and types, role corrections, and durable labels — ride along as
ground truth the model must not contradict; free-text device notes never leave
the host. Responses must cite existing device IDs and include tags, confidence,
and rationale. Invalid IDs or
malformed suggestions are rejected, and accepted suggestions remain separate
from observed evidence.

In the console, a node with pending suggestions shows them in its evidence
panel with two actions: **accept tags** promotes them to durable operator
labels (they survive rescans and feed future tagging runs as ground truth);
**dismiss suggestion** hides them permanently.

## Repository layout

~~~
gui/                   native desktop operator console
cmd/salient/          command-line interface
internal/scan/         shared scan pipeline used by the console and CLI
internal/escli/        read-only Elasticsearch client and field mapping
internal/graph/        dependency graph, evidence, role inference, snapshots
internal/score/        key-terrain scoring
internal/config/       every tunable threshold, port/service tables
internal/mapview/      subnet grouping, gateways, and briefing-map reduction
internal/devices/      operator device registry (links, labels, role overrides)
internal/assist/       model-assisted analysis and device tagging
internal/report/       HTML, SVG, JSON, and GraphML renderers
internal/snapshot/     snapshot storage, artifact indexing, and drift comparison
internal/reconcile/    asset-list reconciliation
web/                   embedded offline map assets
~~~

Additional operator documentation:

- [Architecture and design rationale](ARCHITECTURE.md)
- [Desktop console build and QA](docs/GUI.md)
- [Read-only deployment](docs/DEPLOYMENT.md)
- [Field-map verification](docs/FIELDMAP.md)
- [Map interpretation and export](docs/MAPS.md)
- [Device-config ingestion](docs/config-ingest.md)
- [Security policy](SECURITY.md)

## License

Salient is licensed under the [Apache License 2.0](LICENSE).

Salient uses the
[official Elasticsearch Go client](https://github.com/elastic/go-elasticsearch/blob/v8.19.6/LICENSE),
which is also licensed under Apache-2.0. Salient connects to external
Elasticsearch and Security Onion installations; those platforms remain subject
to their own licenses:

- [Elasticsearch licensing](https://www.elastic.co/licensing/elastic-license)
- [Security Onion license](https://securityonionsolutions.com/license/)
