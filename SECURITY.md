# Security Policy

## Supported Versions

Salient is pre-1.0. Only the latest release gets fixes.

| Version | Supported |
| ------- | --------- |
| latest  | ✅ |
| older   | ❌ |

## Reporting a Vulnerability

Report privately via
[GitHub Security Advisories](https://github.com/BushidoCyb3r/salient/security/advisories/new)
for this repository — do not open a public issue for a security bug.

Expect an initial response within a few days. Confirmed issues get a fix and
a coordinated advisory; declined reports get an explanation.

## Scope

Salient is a **read-only, passive** client: it queries an existing
Elasticsearch/Security Onion deployment and writes only to the local
filesystem (snapshots, reports, maps, operator registries, sanitized declared
models, and optional analysis/tag sidecars). In scope for this policy:

- Vulnerabilities in Salient's own code (the Go binary, the desktop GUI,
  the report/map renderers) — memory safety, injection into generated
  HTML/SVG/GraphML, unsafe handling of API keys or Elasticsearch responses,
  path traversal in snapshot/report file handling.

Out of scope:

- Misconfiguration or vulnerabilities in your own Security Onion / Elasticsearch
  deployment.
- Compromise of the Elasticsearch API key you supply to Salient — protect it
  like any other credential; Salient never transmits it anywhere but your
  configured Elasticsearch endpoint.
- Optional `analyze` and desktop device-tagging calls to an operator-supplied
  model endpoint — that endpoint's security is your responsibility. Salient
  sends only the documented capped summary and requires explicit
  acknowledgement before remote network-data egress.
