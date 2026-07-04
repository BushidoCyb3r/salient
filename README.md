# Defilade

**A desktop operator console for passive terrain analysis on Security Onion grids.**

Defilade connects read-only to Elasticsearch, aggregates existing Zeek telemetry,
and turns observed traffic into a scored dependency graph and briefing map. It is
built for hunting teams that are new to an environment and need to understand its
key systems and dependencies without active scanning or changes to the Security
Onion deployment.

The desktop console is the primary interface. It connects to the grid, runs scans
with live progress, browses saved snapshots, investigates role evidence, and
exports maps from one native window on Linux, macOS, or Windows.

## Operator console

The console provides:

- Elasticsearch connection with API key, CA certificate, custom field map, and
  explicit insecure-TLS controls.
- Configurable scan window, scope CIDRs, and timezone.
- Live scan progress and cancellation.
- Ranked key-terrain maps grouped by subnet, with observed or inferred gateways.
- Organic and tiered layouts, criticality heat, and optional edge labels.
- Snapshot browsing and offline map reconstruction.
- Optional model-assisted device tags based on observed network communication,
  with selectable API shape, endpoint, model, and API key.
- Search by IP, hostname, role, or evidence.
- Node evidence and right-click actions for copying, focusing, and inspecting.
- PNG export of the exact on-screen layout, plus self-contained HTML and GraphML.

Elasticsearch and model API keys remain in memory and are never written to disk.

## Build and run

Prerequisites:

- Git
- Make
- Go 1.26.4 or newer
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
git clone https://github.com/BushidoCyb3r/defilade.git
cd defilade
make gui-deps
make gui
~~~

Launch the resulting application:

~~~sh
# Linux
./gui/build/bin/gui

# macOS
open gui/build/bin/gui.app

# Windows PowerShell
.\gui\build\bin\gui.exe
~~~

Platform-specific runtime packages and unsigned-build warnings are documented in
[docs/GUI.md](docs/GUI.md).

## First connection

1. Create a read-only Elasticsearch API key using
   [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
2. Launch the console and enter the manager URL, API key, and CA certificate.
3. Set the analysis window, timezone, and optional scope CIDRs.
4. Connect, then select **Run Scan**.
5. Select the completed snapshot to inspect and export its map.
6. Optionally configure **AI Device Tagging** and select **Suggest Tags** to add
   communication-based labels to visible devices.

The default Security Onion field map is an unverified starting point because Zeek
to ECS mappings vary by deployment and release. Verify it against the target grid
and record the result in [docs/FIELDMAP.md](docs/FIELDMAP.md) before trusting scan
output. A wrong field map can produce incomplete terrain.

## What a scan produces

Defilade performs server-side Elasticsearch aggregations rather than downloading
raw events. A completed scan writes:

- A compressed snapshot containing scored nodes, dependencies, evidence, and
  observation metadata.
- A detailed analyst report.
- A self-contained interactive briefing map.
- An optional protected `.tags.json` sidecar containing validated model
  suggestions when device tagging is used.

Artifacts are stored under defilade-data/snapshots, defilade-data/reports, and
defilade-data/maps. The console can reopen snapshots without reconnecting to the
grid.

Large unfocused maps are condensed into a briefing overview that retains the
highest-ranked terrain and strongest dependencies. This is intentional, not a
complete-topology view.

## Command line

The CLI remains available for automation, field discovery, static exports, drift
analysis, asset reconciliation, and optional snapshot analysis.

~~~sh
make deps
make build

export DEFILADE_ES_URL="https://so-manager:9200"
export DEFILADE_API_KEY="<base64 id:key>"

./bin/defilade test-connection --ca-cert grid-ca.pem
./bin/defilade discover --ca-cert grid-ca.pem --window 168h
./bin/defilade scan --ca-cert grid-ca.pem --window 336h \
    --scope 10.0.0.0/8 --tz America/New_York
./bin/defilade list
./bin/defilade view
~~~

Stored snapshots can also be rendered as HTML, SVG, JSON, or GraphML; compared
with the diff command; or reconciled against an asset CSV. See
[docs/MAPS.md](docs/MAPS.md) for map interpretation and export guidance.

## Security model

- Elasticsearch access is read-only. Defilade does not change grid
  configuration, indices, or documents.
- The console writes only local snapshots, reports, maps, and operator-selected
  exports.
- Runtime assets are bundled locally. There are no CDN dependencies or telemetry.
- The CLI is a static binary. The desktop console uses the operating system's
  native webview and must be built per target platform.
- Model requests are snapshot-only and send capped, summarized topology. Remote
  endpoints require HTTPS and an explicit network-data-egress acknowledgement.
- Model API keys stay in memory. Tag sidecars record only endpoint host, model,
  timestamp, and validated suggestions.
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
endpoint, model, and credentials issued for that environment; Defilade does not
assume a universal public endpoint.

Only capped node and edge summaries are sent, never raw Zeek events or
Elasticsearch credentials. Responses must cite existing device IDs and include
tags, confidence, and rationale. Invalid IDs or malformed suggestions are
rejected, and accepted suggestions remain separate from observed evidence.

## Repository layout

~~~
gui/                   native desktop operator console
cmd/defilade/          command-line interface
internal/scan/         shared scan pipeline used by the console and CLI
internal/escli/        read-only Elasticsearch client and field mapping
internal/graph/        dependency graph, evidence, and snapshot types
internal/score/        key-terrain scoring
internal/mapview/      subnet grouping, gateways, and briefing-map reduction
internal/report/       HTML, SVG, JSON, and GraphML renderers
internal/snapshot/     snapshot storage, artifact indexing, and drift comparison
internal/reconcile/    asset-list reconciliation
web/                   embedded offline map assets
~~~

Additional operator documentation:

- [Desktop console build and QA](docs/GUI.md)
- [Read-only deployment](docs/DEPLOYMENT.md)
- [Field-map verification](docs/FIELDMAP.md)
- [Map interpretation and export](docs/MAPS.md)

## License

Defilade is licensed under the [Apache License 2.0](LICENSE).

Defilade uses the
[official Elasticsearch Go client](https://github.com/elastic/go-elasticsearch/blob/v8.19.6/LICENSE),
which is also licensed under Apache-2.0. Defilade connects to external
Elasticsearch and Security Onion installations; those platforms remain subject
to their own licenses:

- [Elasticsearch licensing](https://www.elastic.co/licensing/elastic-license)
- [Security Onion license](https://securityonionsolutions.com/license/)
