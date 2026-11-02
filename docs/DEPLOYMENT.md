# Deployment on the Tenable VM

The connector runs on the VM that hosts Security Center (or on any Linux VM that can reach it). The workstation only needs port 8000 (the Studio and the API); Security Center is reached locally on 443, Nessus on 8834 when it is the source.

## 1. Prerequisites

- Linux VM with Python 3.11 or later (`python3 --version`), outbound access to the Security Center URL, inbound 8000 from the workstation subnet.
- A Security Center user for the connector. A read-only role is enough: it needs to see the vulnerability analysis of every repository in scope, the Accept/Recast Risk rules and the scan results. The built-in **Auditor** role with access to all repositories works; a custom role with "View Vulnerability Analysis" and the rule listing permissions is tighter.
- API keys for that user: **Users** → the user → **Generate API Keys** (Security Center 5.13 and later). Keep the secret key; it is shown once.

## 2. Install

```bash
sudo useradd --system --home /opt/trs-connector --shell /usr/sbin/nologin trs
sudo mkdir -p /opt/trs-connector /etc/trs-connector /var/lib/trs-connector
sudo git clone <this repository> /opt/trs-connector/src      # or copy the folder
cd /opt/trs-connector
sudo python3 -m venv venv
sudo venv/bin/pip install ./src/connector
sudo venv/bin/trs-connector init-config /etc/trs-connector/config.yaml
```

Edit `/etc/trs-connector/config.yaml`:

```yaml
sc:
  url: https://127.0.0.1            # Security Center on this VM; otherwise https://<security-center-host>
  verify: false                     # true or a CA bundle path once the SC certificate is trusted
server:
  port: 8000
  public_url: http://<tenable-vm>:8000
  auth:
    username: studio
store:
  dir: /var/lib/trs-connector/data
schedule:
  weekday: Mon
  time: "06:00"
  timezone: Asia/Riyadh
studio:
  path: /opt/trs-connector/src/studio/ALTANFEETHI_Tenable_Report_Studio.html
```

Secrets go in `/etc/trs-connector/env` (never in the config file in git):

```bash
sudo tee /etc/trs-connector/env >/dev/null <<'EOF'
TRS_SC_ACCESS_KEY=...
TRS_SC_SECRET_KEY=...
TRS_AUTH_PASSWORD=...
EOF
sudo chown root:trs /etc/trs-connector/env /etc/trs-connector/config.yaml
sudo chmod 640 /etc/trs-connector/env /etc/trs-connector/config.yaml
sudo chown -R trs:trs /var/lib/trs-connector
```

## 3. Check the connection and the field mapping

```bash
sudo -u trs env $(cat /etc/trs-connector/env | xargs) /opt/trs-connector/venv/bin/trs-connector --config /etc/trs-connector/config.yaml probe
```

`probe` prints the Security Center version, the API user, the repositories, the number of vulnerability and compliance rows the pull will fetch, and for every export column the record field it comes from. A column marked "(not in the record)" means this Security Center version names the field differently: the candidates are in `trs_connector/export_schema.py` (`COLUMNS`); add the name reported under "Record fields with no export column" and reinstall.

Then run one pull by hand and look at the result:

```bash
sudo -u trs env $(cat /etc/trs-connector/env | xargs) /opt/trs-connector/venv/bin/trs-connector --config /etc/trs-connector/config.yaml pull
sudo -u trs /opt/trs-connector/venv/bin/trs-connector --config /etc/trs-connector/config.yaml list
```

A pull of the 25 Oct volumes (5,800 vulnerability rows, 33,000 compliance rows with plugin output) takes a few minutes; the compliance page size (`sc.compliance_page_size`, default 1000) is the knob if Security Center times out on large pages.

## 4. Run as a service

```bash
sudo cp /opt/trs-connector/src/connector/deploy/trs-connector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trs-connector
sudo journalctl -u trs-connector -f
```

The unit runs as the `trs` user, reads the secrets from `/etc/trs-connector/env` and restarts on failure.

## 5. Firewall

Open 8000 from the workstation subnet only, for example with firewalld:

```bash
sudo firewall-cmd --permanent --new-zone=studio
sudo firewall-cmd --permanent --zone=studio --add-source=10.200.0.0/16
sudo firewall-cmd --permanent --zone=studio --add-port=8000/tcp
sudo firewall-cmd --reload
```

## 6. TLS

HTTP basic authentication sends the password with every request; on anything but a closed segment serve HTTPS. Either terminate TLS in a reverse proxy, or give the connector a certificate:

```bash
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=<tenable-vm>" \
  -keyout /etc/trs-connector/key.pem -out /etc/trs-connector/cert.pem
sudo chown root:trs /etc/trs-connector/*.pem && sudo chmod 640 /etc/trs-connector/*.pem
```

```yaml
server:
  tls:
    certfile: /etc/trs-connector/cert.pem
    keyfile: /etc/trs-connector/key.pem
  public_url: https://<tenable-vm>:8000
```

Import the certificate on the workstations (or issue one from the internal CA) so the browser does not warn.

## 7. First use

1. Open `http://<tenable-vm>:8000/` (or https) and sign in with `server.auth`.
2. Click **Tenable** → **Pull now**; the panel follows the pull (rows fetched per query, duration).
3. Tick the pull and click **Load selected pull**: the Studio loads the two exports exactly as if they had been dropped on it. Tick an older pull as well to get the trend, **Validate fixes** and the register closures.
4. **Settings** (segmentation rules, timelines, internet-facing hosts) and **Risk settings** are now kept on the server and shared by everyone who opens the hosted Studio; the archive's `settings.json` remains the backup.
5. The weekly pull runs by itself (Monday 06:00 Riyadh by default); the next run is shown in the panel.

Every browser profile that opens the hosted Studio keeps its own `localStorage`/IndexedDB cache, but reads the server copy first; a Studio opened from a folder (file://) does not see the server state.

## 8. Nessus (port 8834) as the source

When Security Center is not the source, point the connector at Nessus Manager / Nessus:

```yaml
sc:
  enabled: false
nessus:
  enabled: true
  url: https://127.0.0.1:8834
  verify: false
  scans: ["Weekly VA - all servers", "Agent VA + CIS"]   # empty = every completed scan of the last max_age_days
  max_age_days: 45
```

API keys: Nessus → **My Account** → **API Keys**. Nessus has no "first discovered": the connector carries it forward from its previous pull, so the first pull dates every finding at its scan time.

## 9. Operations

- **Where the data is:** `/var/lib/trs-connector/data/<date>/` per pull, `_state/` for the shared settings and register (back this folder up; the register is the history of closures and overrides).
- **Retention:** `store.retention_days` (default 400) removes old pulls after a successful pull; failed pulls are kept 7 days for their manifest.
- **A new Studio version:** replace the HTML file; the service re-reads it on the next request. Keep the file in this repository and apply changes through `tools/patch_studio.py` where possible.
- **Logs:** `journalctl -u trs-connector`; every pull writes its progress log in the job (`/api/jobs`) and its outcome in `manifest.json`.
- **Health:** `GET /healthz` needs no authentication (for a monitoring probe).

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `HTTP 403 (check the API keys…)` | wrong keys, or the user has no access to the repository / analysis. Regenerate the keys; check the user's role and repository access. |
| `Security Center does not accept the filter 'wasVuln'; retrying without it` | an older Security Center; harmless (logged once per pull), or set `sc.exclude_was: false`. |
| `certificate verify failed` | `sc.verify: false`, or the CA bundle path that signed the Security Center certificate. |
| `the response is not JSON (is this the Security Center URL?)` | the URL points at the Nessus port or a proxy; use the Security Center web UI URL without a path. |
| a pull takes very long or times out | lower `sc.compliance_page_size` (500) and `sc.page_size`; raise `sc.timeout`. |
| the browser downloads `.gz` files | a proxy strips `Content-Encoding`; set `store.compress: false`. |
| the panel is missing in the Studio | the page was opened from a folder, not from the connector; or the browser cached an old copy (hard reload). |
| port 8000 in use | `server.port`, and the firewall rule. |
