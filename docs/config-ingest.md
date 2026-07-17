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

### UniFi

Salient needs three JSON collections from UniFi: networks, firewall rules, and
devices. Import all three files together; Salient folds them into one declared
controller.

Ubiquiti documents [local console access](https://help.ui.com/hc/en-us/articles/28457353760919-UniFi-Local-Management),
[local administrator creation](https://help.ui.com/hc/en-us/articles/28692158912279-Adding-Admins-in-UniFi),
and the [official Network API](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API).
The export endpoints below are the controller's legacy, version-sensitive API,
so validate every response before importing it.

> **The API key from Network → Integrations does not work with this importer.**
> That key authenticates UniFi's official `/integration/v1` API, whose network
> and firewall schemas differ from the legacy controller-export schemas that
> Salient currently parses. For now, use a local controller session as described
> below. Do not paste the session cookie into Salient; use it only to make the
> three local exports.

#### UDM Pro and other UniFi OS consoles

These steps run on a trusted workstation with Bash, `curl`, and `jq`. Connect
directly to the console's LAN address, such as `https://192.168.1.1`; do not use
`unifi.ui.com`. The account is a UniFi console administrator, not the gateway's
SSH `root` account.

1. Set the local console address and create a private, temporary cookie jar:

   ```bash
   umask 077
   UDM_BASE='https://192.168.1.1'
   UDM_COOKIE_JAR=$(mktemp)
   trap 'rm -f "$UDM_COOKIE_JAR"' EXIT
   ```

2. Log in. The password is read without echoing and is not put in shell
   history or the `curl` process arguments:

   ```bash
   read -rp 'Local UDM admin username: ' UDM_USER
   read -rsp 'Local UDM admin password: ' UDM_PASSWORD
   printf '\n'
   export UDM_USER UDM_PASSWORD
   jq -n '{username: env.UDM_USER, password: env.UDM_PASSWORD}' |
     curl -kfsS --remove-on-error \
       -c "$UDM_COOKIE_JAR" \
       -H 'Content-Type: application/json' \
       --data-binary @- \
       "$UDM_BASE/api/auth/login" >/dev/null
   unset UDM_USER UDM_PASSWORD
   ```

   `-k` accepts the self-signed certificate commonly used by local consoles.
   Omit it if the certificate is trusted, or replace it with
   `--cacert /path/to/console-ca.pem` when you have the issuing CA.

3. Discover the controller's URL site name:

   ```bash
   curl -kfsS -b "$UDM_COOKIE_JAR" \
     "$UDM_BASE/proxy/network/api/self/sites" |
     jq -r '.data[] | [.name, .desc] | @tsv'
   ```

   The first column (`name`) is the value required in the export URLs. The
   second (`desc`) is the display name. Most single-site UDM Pro installations
   use `default` even when the displayed site name has been changed:

   ```bash
   UDM_SITE='default'
   ```

4. Export all three collections:

   ```bash
   curl -kfsS --remove-on-error -b "$UDM_COOKIE_JAR" \
     "$UDM_BASE/proxy/network/api/s/$UDM_SITE/rest/networkconf" \
     -o unifi-networkconf.json
   curl -kfsS --remove-on-error -b "$UDM_COOKIE_JAR" \
     "$UDM_BASE/proxy/network/api/s/$UDM_SITE/rest/firewallrule" \
     -o unifi-firewallrule.json
   curl -kfsS --remove-on-error -b "$UDM_COOKIE_JAR" \
     "$UDM_BASE/proxy/network/api/s/$UDM_SITE/stat/device" \
     -o unifi-device.json
   ```

5. Verify that every file is authenticated JSON with a successful controller
   response and an array of records:

   ```bash
   for file in unifi-networkconf.json unifi-firewallrule.json unifi-device.json; do
     jq -e '.meta.rc == "ok" and (.data | type == "array")' "$file" >/dev/null || {
       echo "invalid or unauthorized export: $file" >&2
       exit 1
     }
   done
   ```

6. Remove the session credential. The `EXIT` trap is a second safeguard if the
   shell closes earlier:

   ```bash
   rm -f "$UDM_COOKIE_JAR"
   trap - EXIT
   unset UDM_COOKIE_JAR UDM_BASE UDM_SITE
   ```

If `/api/auth/login` returns `401` because your account uses UI Account SSO or
MFA, obtain the already-authenticated browser session instead:

1. Browse directly to `https://<UDM-LAN-IP>`, sign in, and open the Network
   application.
2. Open Developer Tools (or Safari's Web Inspector), select **Network**, enable
   **Preserve log**, and reload the page.
3. Filter requests for `proxy/network/api`. Select an authenticated `GET` whose
   path contains `/proxy/network/api/s/<site>/`; `<site>` is the URL site name.
4. In **Headers → Request Headers**, copy the complete value after `Cookie:`.
   If the header is hidden, inspect **Application/Storage → Cookies** for the
   local UDM origin. The session cookie is often named `TOKEN`, but use the
   name and value actually shown by your console.
5. Read it into a temporary shell variable without echoing it:

   ```bash
   read -rsp 'Paste Cookie header value: ' UDM_COOKIE
   printf '\n'
   ```

   Run the three export commands above with `-b "$UDM_COOKIE"` in place of
   `-b "$UDM_COOKIE_JAR"`, validate the files, then run
   `unset UDM_COOKIE`. A cookie is a live credential: never save it in a script,
   commit it, paste it into Salient, or share it with the exported files.

If you need a dedicated local administrator, connect directly to the console
and use **Network → Admins → +**. Give it only the controller access needed to
read Network configuration. Do not disable MFA on an existing UI Account just
to use the command-line login.

#### Legacy self-hosted controller

Older self-hosted controllers normally use port `8443`, authenticate at
`/api/login`, and omit `/proxy/network` from every API path. After obtaining a
cookie jar, discover sites at `/api/self/sites` and export:

```bash
UNIFI_BASE='https://192.168.1.10:8443'
UNIFI_SITE='default'
curl -kfsS -b "$UNIFI_COOKIE_JAR" "$UNIFI_BASE/api/s/$UNIFI_SITE/rest/networkconf"  -o unifi-networkconf.json
curl -kfsS -b "$UNIFI_COOKIE_JAR" "$UNIFI_BASE/api/s/$UNIFI_SITE/rest/firewallrule" -o unifi-firewallrule.json
curl -kfsS -b "$UNIFI_COOKIE_JAR" "$UNIFI_BASE/api/s/$UNIFI_SITE/stat/device"       -o unifi-device.json
```

Validate and remove the cookie jar exactly as for UniFi OS.

#### Troubleshooting and coverage

- `401` or `403`: the session is absent, expired, or lacks Network access.
  Authenticate directly to the local console again; a Network Integration API
  key is not interchangeable with the session cookie.
- A saved file starts with HTML: the request reached a login page, often
  because it used `unifi.ui.com` or an expired session. Use the local console
  address and repeat the `jq` validation.
- `api.err.NoSiteContext` or unexpectedly empty data: list sites again and use
  the `name` value, not the displayed `desc` value.
- The firewall export validates but is empty while rules exist in the UI: keep
  the files and record the UniFi Network version, but do not treat the import as
  policy-complete. That controller's firewall schema is not represented by the
  legacy collection Salient currently understands.

Salient autodetects the exported JSON wrapper (`{"meta": ..., "data": [...]}`)
or a bare array. Networks provide VLANs and subnets, `firewallrule` provides
rules, and `stat/device` associates controller devices with observed MACs.

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
