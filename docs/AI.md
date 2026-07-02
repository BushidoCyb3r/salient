# Optional model-assisted analysis

`defilade analyze` sends a capped summary of a stored snapshot to a
chat-completions-compatible endpoint. It is never invoked by `scan`, `map`,
`report`, or `diff`; ordinary Defilade operation makes no outbound calls.

Use this mode for analyst summaries, dependency explanations, blind-spot
review, and hunting hypotheses. Defilade remains authoritative for observed
topology, scoring, and evidence. Model findings are stored separately and
cannot modify a snapshot.

## Local endpoint

```sh
./bin/defilade analyze \
  --snapshot defilade-data/snapshots/<ts>.json.gz \
  --endpoint http://127.0.0.1:11434/v1/chat/completions \
  --model local-model
```

Loopback HTTP endpoints are allowed without an egress flag. Defilade does not
start or manage the model server.

## Remote endpoint

```sh
export DEFILADE_AI_API_KEY='<endpoint credential>'

./bin/defilade analyze \
  --snapshot defilade-data/snapshots/<ts>.json.gz \
  --endpoint https://approved.example/v1/chat/completions \
  --model approved-model \
  --allow-network-data-egress
```

Remote endpoints require HTTPS and the explicit
`--allow-network-data-egress` acknowledgement. Enforce the intended route and
destination with host firewall and routing policy, especially on dual-homed
hunt systems. The flag grants no bypass around operating-system controls.

## Data sent

The default request contains at most the top 100 ranked nodes and 500
highest-volume edges whose endpoints are both included. It includes IPs,
hostnames, subnets, inferred roles and evidence, scores, ports, services, and
aggregate connection counts. It excludes Elasticsearch credentials, raw Zeek
events, sensor names, and snapshot timestamps.

Use `--max-nodes` and `--max-edges` to reduce disclosure further. Treat the
request and resulting `.analysis.json` file at the classification or
sensitivity of the network described.

## Integrity boundary

The endpoint must return structured JSON findings citing supplied node or edge
IDs. Defilade rejects unknown or missing citations. This prevents unsupported
topology from being silently accepted, but it does not make model conclusions
authoritative; analysts must verify every hypothesis against the attached
evidence.
