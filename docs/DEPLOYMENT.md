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

## 2. Create a read-only role and API key

In Kibana Dev Tools (or `curl` as an admin user):

```json
POST /_security/role/defilade_readonly
{
  "indices": [
    {
      "names": ["logs-*"],
      "privileges": ["read", "view_index_metadata"]
    }
  ]
}

POST /_security/api_key
{
  "name": "defilade",
  "role_descriptors": {
    "defilade_readonly": {
      "indices": [
        { "names": ["logs-*"], "privileges": ["read", "view_index_metadata"] }
      ]
    }
  }
}
```

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
