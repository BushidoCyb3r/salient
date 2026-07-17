# Deployment: read-only access to the SO grid

For its core scan workflow, Salient runs on an analyst workstation and needs
HTTPS reach to the manager's Elasticsearch API (:9200) with a read-only API
key. Salient makes no changes to Security Onion; an administrator may need to
allow the workstation through the grid firewall as described below. The
optional `unifi-export` command separately needs local HTTPS reach to the UniFi
console and a Network Integration API key; see
[config ingestion](config-ingest.md).

## 1. Allow your workstation through the SO firewall

Security Onion manages its host firewall through the grid configuration. In
SOC, open **Administration → Configuration → firewall**, enable **Show advanced
settings**, then:

1. Add the analyst workstation IP to a custom host group.
2. Add TCP 9200 to a custom port group.
3. Associate that host group and port group with the Elasticsearch node the
   workstation will contact (the manager in the common single-manager path).
4. Save and **SYNCHRONIZE GRID** to apply the rule immediately.

The exact role and chain depend on the grid's node layout. Follow Security
Onion's official
[host-group and port-group procedure](https://docs.securityonion.net/en/2.4/firewall.html#creating-a-custom-host-group-with-a-custom-port-group)
and expose only TCP 9200 to the specific workstation. Do not edit `iptables`
directly: Security Onion's Salt-managed configuration can overwrite it. The
`so-firewall includehost analyst` shortcut is for SOC web access and does not
grant this Elasticsearch path.

## 2. Create a read-only API key

The key needs two things: the cluster `monitor` privilege (Salient calls the
Elasticsearch root `info` API at connect — without it you get
`action [cluster:monitor/main] is unauthorized ... HTTP 403`) and `read` +
`view_index_metadata` on the Zeek log indices. Nothing writable.

### Option A — Kibana UI (Stack Management)

1. **Stack Management → Security → API keys → Create API key**.
2. **Name:** `salient_readonly`.
3. Toggle **Control security privileges** on. A code editor appears — select all
   of its contents, delete them, and paste *only* this (no `POST` line, no outer
   `name` key):

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

   `indices` stays an **array** — if Kibana reports "expected object, found
   Array," there is leftover text above or below your paste; the editor must
   contain exactly the object above and nothing else.
4. **Create API key**, then switch the result's format dropdown to **Base64** and
   copy that value — it is the `encoded` (`base64(id:api_key)`) form the console
   wants.

### Option B — Kibana Dev Tools (or `curl` as an admin user)

```json
POST /_security/api_key
{
  "name": "salient_readonly",
  "role_descriptors": {
    "salient_ro": {
      "cluster": ["monitor"],
      "indices": [
        { "names": ["logs-*"], "privileges": ["read", "view_index_metadata"] }
      ]
    }
  }
}
```

If your Zeek logs are not under `logs-*`, change `names` to match the index
pattern you configure in the field map.

Use the `encoded` value from the response:

```sh
export SALIENT_ES_URL="https://<manager>:9200"
export SALIENT_API_KEY="<encoded>"
```

`salient test-connection` verifies the key cannot write; it warns in red if it can.

## 3. TLS

Fetch the grid CA once and pass it with `--ca-cert`:

```sh
scp so-manager:/etc/pki/ca.crt grid-ca.pem   # path varies by SO version
salient test-connection --ca-cert grid-ca.pem
```

`--insecure-skip-verify` works but prints a red warning every run. Don't make it a habit.
