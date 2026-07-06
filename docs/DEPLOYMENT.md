# Deployment: read-only access to the SO grid

Defilade runs on an analyst workstation and needs exactly one thing: HTTPS reach to
the manager's Elasticsearch API (:9200) with a read-only API key. No SO changes.

## 1. Allow your workstation through the SO firewall

On the manager, as an admin:

```sh
sudo so-firewall includehost elastic_agent <workstation-ip>   # SO 2.4: role granting 9200
sudo so-firewall apply
```

> Verify the correct role name for your SO version with `sudo so-firewall listhosts`
> — the goal is TCP 9200 from your workstation to the manager, nothing more.

## 2. Create a read-only API key

The key needs two things: the cluster `monitor` privilege (Defilade calls the
Elasticsearch root `info` API at connect — without it you get
`action [cluster:monitor/main] is unauthorized ... HTTP 403`) and `read` +
`view_index_metadata` on the Zeek log indices. Nothing writable.

### Option A — Kibana UI (Stack Management)

1. **Stack Management → Security → API keys → Create API key**.
2. **Name:** `defilade_readonly`.
3. Toggle **Control security privileges** on. A code editor appears — select all
   of its contents, delete them, and paste *only* this (no `POST` line, no outer
   `name` key):

   ```json
   {
     "defilade_ro": {
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
  "name": "defilade_readonly",
  "role_descriptors": {
    "defilade_ro": {
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
export DEFILADE_ES_URL="https://<manager>:9200"
export DEFILADE_API_KEY="<encoded>"
```

`defilade test-connection` verifies the key cannot write; it warns in red if it can.

## 3. TLS

Fetch the grid CA once and pass it with `--ca-cert`:

```sh
scp so-manager:/etc/pki/ca.crt grid-ca.pem   # path varies by SO version
defilade test-connection --ca-cert grid-ca.pem
```

`--insecure-skip-verify` works but prints a red warning every run. Don't make it a habit.
