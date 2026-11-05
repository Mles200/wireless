# Tenable Pull: the fetch step, explained

Two files, one job each. **The Studio** (`ALTANFEETHI_Tenable_Report_Studio.html`) makes the report and, since v4.8, fetches the exports itself under its **Tenable** button. **Tenable Pull** (`Tenable_Pull.html`) is a helper that only fetches: the same form, the same pull, but it stops at the two CSV files (download them, or hand them to the Studio with one click). For the weekly report the Studio alone is enough; the helper is for when you want the CSV files on their own. Nothing is installed and nothing leaves the computer except the requests to the endpoint you typed.

## 0. The form, field by field

**Which product do I connect to?** *Tenable Security Center* (Tenable.sc) is the management console, the one with *Analysis › Vulnerabilities*, *Repositories*, *Organizations*, *Accept Risk*, where the CSV exports were taken by hand until now; it keeps the cumulative results with first-seen and last-seen dates. Use this one. *Nessus / Nessus Manager* is the scanner itself (console with *Scans*, *Agents*, *Policies*, port 8834); the agents report to it and Security Center imports from it. Use it only without Security Center: same findings, no history, no Accept/Recast Risk rules. Not sure? Leave Source on *Detect automatically*: Check connection asks the address as Security Center first, then as Nessus, and reports what answered.

| Field | What to enter | Example |
|---|---|---|
| Source | *Detect automatically* (recommended), or the product explicitly | |
| API endpoint | The address you type in the browser to open that console, no path after it; add the port if the console is reached on one. The tool adds `/rest/…` or the Nessus paths itself. | `https://10.70.30.2`, `https://tenable.altanfeethi.local`, `https://10.70.30.2:8000`, `https://10.70.30.2:8834` (Nessus) |
| Access key, Secret key | API keys of a read-only service account. Security Center: *Users › the user › Generate API Keys* (allowed under *Settings › Configuration › Security › Allow API Keys*; the Auditor role with access to every repository is enough). Nessus: *My Account › API Keys*. The secret is shown once. | |
| Username, password | Security Center only, instead of keys: a session login like the console's, logged out at the end. Keys are preferred. | |
| Remember | Unticked: address, access key and options stay in this browser profile, the secret only until the tab is closed. Ticked: the secret is kept too, unencrypted. | |
| Pull options | Severities (the report uses Critical to Low), inventory rows (keep on), compliance export (keep on), request pacing, repositories or scans to include (listed after Check connection; none ticked = all). Nessus only: a previous VA export to carry the first-seen dates forward. | |

## 1. What a pull does

| Step | Security Center (REST API) | Nessus / Nessus Manager (port 8834) |
|---|---|---|
| Check connection | `/rest/system`, `/rest/currentUser`, `/rest/repository` | `/server/properties`, `/scans` |
| Vulnerabilities | `/rest/analysis`, cumulative, tool `vulndetails`, severities Critical to Low, the ticked repositories (none ticked = all) | the completed scans you tick (none = every completed scan of the last 45 days), exported as `.nessus` and parsed in the page |
| Inventory rows | severity Info restricted to plugins 11936, 55472, 19506, 45590, 209654, so hosts without findings stay listed as "scanned, no findings" (this is what makes "Validate fixes" and the register closures conclusive) | included in the scan export |
| Compliance | `pluginType = compliance`, severities Info (passed), Medium (warning), High (failed) | the compliance items of the scans, with the `Result / Actual Value / Policy Value / Solution` block the Studio parses |
| Audit data | Accept Risk and Recast Risk rules, scan results of the last 45 days | the scan list |

Output: `SC VA export <date>.csv` and `SC Compliance export <date>.csv` (or `Nessus …`), UTF-8 with BOM, dates in ISO 8601 UTC, plus `manifest.json` (counts, filters, which Security Center field each column came from, the load figures) and `risk-rules.json`. Rows stored in two repositories are kept, as in the UI export; the Studio removes them and reports the reconciliation. For Nessus, each compliance check gets a stable plugin ID in the Security Center range and **First Discovered** is carried forward from the previous export when you select it under Pull options.

## 2. Set-up

1. **A service account in Security Center** with a read-only role that can see every repository in scope (the built-in Auditor role works), and API keys for it: **Users** → the user → **Generate API Keys**. API keys must be allowed under **Settings → Configuration → Security → Allow API Keys**. Nessus: **My Account → API Keys**.
2. **The certificate.** A page cannot ask you to accept a certificate. If the endpoint uses a self-signed one, open it once in a new tab (the link next to the buttons points at `/rest/system`), accept the warning or import the internal CA, then retry.
3. **Where the keys live.** With "Remember" unticked, the access key, endpoint and options are kept in the browser profile and the secret only until the tab is closed; ticked, the secret is kept too (unencrypted, in the profile, like any saved password). The keys are sent only to the endpoint you entered.

## 3. Where the file runs: the one thing to decide

A page may only read another server's answers when that server allows it, through the `Access-Control-Allow-Origin` response header (CORS). **Security Center and Nessus do not send it by default**, so a `Tenable_Pull.html` opened from a folder gets a plain network failure even though the server is reachable; "Check connection" says so explicitly. Pick one of these:

**A. Serve the file from the Security Center server (recommended).** Same origin, nothing to allow, nothing to maintain in the browser: copy `Tenable_Pull.html` and the Studio into the Security Center web root (the `DocumentRoot` named in `/opt/sc/support/conf/*.conf`) and open `https://<security-center>/Tenable_Pull.html`. The files are static; keep a copy outside the web root because an upgrade can replace the folder. Not available for Nessus, whose web server serves no extra files.

**B. Allow the page on the Security Center side.** In the Apache configuration of Security Center (the SSL virtual host under `/opt/sc/support/conf/`), add, then restart Security Center (`service SecurityCenter restart`):

```apache
<IfModule mod_headers.c>
  # "null" is the origin of a page opened from a folder; use the serving origin instead when the file is served from a web server
  SetEnvIf Origin "^null$" TRS_ORIGIN=$0
  Header always set Access-Control-Allow-Origin "%{TRS_ORIGIN}e" env=TRS_ORIGIN
  Header always set Access-Control-Allow-Headers "X-APIKey, X-SecurityCenter, Content-Type, Accept"
  Header always set Access-Control-Allow-Methods "GET, POST, DELETE, OPTIONS"
  Header always set Access-Control-Expose-Headers "Retry-After"
  Header always set Access-Control-Max-Age "600"
</IfModule>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} OPTIONS
RewriteRule ^/rest/ - [R=204,L]
```

Tenable does not support edits to this configuration: keep a copy and re-apply after an upgrade. Allowing the `null` origin lets any file opened from a folder on any workstation talk to the API with valid keys; the keys remain the credential. Nessus has no equivalent setting.

**C. A dedicated browser profile without web security**, used for nothing else: a shortcut such as

```
"C:\Program Files\Google\Chrome\Application\chrome.exe" --user-data-dir="%LOCALAPPDATA%\TenablePull" --disable-web-security "C:\Tenable\Tenable_Pull.html"
```

The profile has no same-origin protection at all; never browse other sites in it. This is the quickest way to try the tool today and the weakest to live with.

**D. The optional connector service** (`connector/`), which pulls server-side on a schedule and serves the Studio; see `connector/DEPLOYMENT.md`. Not needed for A to C.

## 4. Not breaking Security Center

Every page of the vulnerability analysis is a database query on Security Center. The tool therefore:

- sends **one request at a time**, never in parallel, and **waits between requests** (pacing under Pull options: Gentle 2 s, Normal 0.75 s, Fast 0.15 s);
- uses **moderate pages**: Normal pulls 1,000 vulnerability rows and 500 compliance rows per request (Gentle 500 / 250, Fast 2,500 / 1,000; editable, capped at 5,000);
- gives a request **up to 2 minutes** (3 under Gentle), then retries;
- when the server answers **429, 502, 503 or 504**, waits the `Retry-After` it asks for, otherwise 2 s, 4 s, 8 s… up to 60 s with jitter, and retries up to 3 times (4 under Gentle, 2 under Fast);
- polls a Nessus export status **no more than every 3 s**;
- stops at 20,000 requests in one pull as a safety limit, and never retries a check of the connection.

The result shows the figures: number of requests, time paused, time the server spent, slowest request, retries. A pull of the current estate (about 6,000 vulnerability rows and 33,000 compliance rows) is roughly 75 requests under Normal pacing. Run it outside the scan windows.

## 5. Loading the result into the Studio

- **From the tool:** "Open the Studio and load these files" opens the Studio file named in the box (the Studio in the same folder by default, or a full path or URL) and hands the files over; the Studio must be v4.8 or later and the browser must allow the pop-up. Or download the two CSVs and drop them on the Studio.
- **From the Studio:** the **Tenable** button opens the same panel inside the Studio; after the pull the files are loaded directly, exactly like dropped exports (dating, "now" / history, de-duplication, the archive's source folder, the Excel source sheets). Loading an earlier pull's CSVs next to today's gives the trend, "Validate fixes" and the register closures as before.

The hand-over only accepts files from the window that opened the Studio.

## 6. Troubleshooting

| Message | Meaning and fix |
|---|---|
| "The browser could not get an answer from …" after Check connection | The tool then runs a diagnosis. **"Diagnosis: the server is there"**: the address, network and certificate are fine; the server only refuses to let the page read the answer (CORS), so pick an option from section 3. **"Diagnosis: no connection at all"**: open the endpoint link in a new tab; a certificate warning means accept it and retry; "can't be reached" means the address or port is wrong or blocked, so use the address you log in to the console with, port included; the diagnosis also lists which of the usual ports (443, 8000, 8443, 8834) answered on that host. |
| "HTTP 403 … Invalid API key" | wrong keys, API keys not allowed in Security Center, or the user cannot see the repository. |
| "… did not return JSON" | the endpoint is a login page or the wrong port; use the Security Center web UI address without a path, or `https://host:8834` for Nessus. |
| "Security Center does not accept the filter wasVuln" in the log | an older Security Center; the filter is dropped and the pull continues. |
| "No answer … within 120 s" | lower the page sizes or choose Gentle pacing. |
| "HTTP 429 … rate limiting" after the retries | the server is busy; wait and run again with Gentle pacing. |
| Columns listed as "did not return" after the pull | this Security Center names those fields differently; the record fields with no column are in `manifest.json` (`mapping`); send that file to adjust `COLUMNS` in `studio/src/tenable_pull.js`. |
| "The Studio did not answer" after "Open the Studio…" | pop-ups blocked, or the Studio file is older than 4.8 or not at that path; download the files and drop them instead. |

## 7. Limits

- Everything happens in the browser's memory: the compliance export of the current estate (about 110 MB of text) is built and parsed in the page, as before with a dropped file.
- The Security Center field names of the newest columns (EPSS, Security End of Life, Host ID, Agent ID, rule comments) could not be verified against a live system from where this was built; the tool lists candidates and reports what it found (see the table above).
- Nessus has no cumulative view: First Discovered is only as old as the previous export you select.
- The engine source is `studio/src/tenable_pull.js`; `tools/build_tenable.py` inlines it into `Tenable_Pull.html` and the Studio. `node --test studio/src/tenable_pull.test.mjs` runs its unit checks; the browser tests are in `connector/tests/test_pull_tool.py`.
