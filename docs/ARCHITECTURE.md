# Architecture

## Components

```
┌──────────────────────────── Tenable VM ─────────────────────────────┐
│                                                                      │
│  Security Center ◀──:443 (REST, API keys)──┐                         │
│  Nessus Manager  ◀──:8834 (optional)───────┤                         │
│                                            │                         │
│                                   trs-connector (Python, FastAPI)    │
│                                   ├─ scheduler: weekly pull          │
│                                   ├─ store: /var/lib/trs-connector   │
│                                   │    2026-11-03/ SC VA export…csv.gz│
│                                   │                SC Compliance…csv.gz│
│                                   │                risk-rules.json    │
│                                   │                scans.json         │
│                                   │                manifest.json      │
│                                   │    _state/ settings.json, register.json │
│                                   └─ HTTP :8000 (basic auth, optional TLS)   │
└──────────────────────────────────────┬───────────────────────────────┘
                                       │
                 workstation browser ◀─┘  GET /  → the Studio + connector.js
                                          Tenable panel → /api/exports/… → addFiles()
```

## The pull

`trs_connector/exporter.py` runs three `vulndetails` analysis queries against the cumulative source and routes the rows by their nature, not by the query that returned them:

| Query | Filters | Goes to |
|---|---|---|
| vulnerabilities | severity 4,3,2,1 (Critical to Low), the configured repositories, `wasVuln = excludeWas` | VA export |
| inventory | severity 0 restricted to plugins 11936, 55472, 19506, 45590, 209654 | VA export (Info rows: the Studio uses them for OS, host names and "scanned, no findings") |
| compliance | `pluginType = compliance`, severities 0,1,2,3,4 (Info = passed, Medium = warning, High = failed) | Compliance export |

A row whose family type is `compliance` or whose plugin ID is 1,000,000 or more is a check; everything else is a vulnerability. Rows returned twice (a failed check comes back from the vulnerability query too) are written once; the key is plugin, host, port, protocol and repository, plus the check name for compliance rows. Rows stored in two repositories are kept, as in the UI export: the Studio's own de-duplication and its "Data check" reconciliation stay meaningful.

The client (`sc_client.py`) pages with `startOffset`/`endOffset` like pyTenable, and drops a filter the installed version does not know (error 146, "The filter 'x' is invalid") with a warning instead of failing, so `wasVuln` does not break an older Security Center.

After the exports the pull fetches the Accept Risk and Recast Risk rules (`/rest/acceptRiskRule`, `/rest/recastRiskRule`) and the scan results of the last 45 days (`/rest/scanResult`), writes `manifest.json` (counts, filters, source version and user, timings, warnings) and applies the retention.

### The export files

`export_schema.py` fixes the column order and the header names: the ones of the Security Center "Vulnerability Detail List" export, written exactly as the Studio's alias table expects them (`Plugin`, `Plugin Name`, `Family`, `Severity`, `IP Address`, …, `Plugin Text`, `Steps to Remediate`, `First Discovered`, `Last Observed`, `Host ID`, `Agent ID`, `Accept Risk Comment`, `Recast Risk Comment`). Dates are ISO 8601 UTC (`2026-10-25T06:12:33Z`), the one format every JavaScript engine parses the same way. Files are UTF-8 with a BOM (Excel opens them correctly; the Studio strips it) and gzip-compressed on disk; the service sends them with `Content-Encoding: gzip`, so the browser receives plain CSV.

The mapping from the record fields to the columns lists candidate field names per column; `trs-connector probe` prints which field each column came from on the real Security Center and which columns, if any, it did not return. Fields the connector does not know are reported, not lost silently.

### Nessus as the source

`nessus_source.py` lists the completed scans, exports each as `.nessus`, parses it with `iterparse` and builds the same records (host properties, plugin attributes, compliance checks with the `Result / Actual Value / Policy Value / Solution / See Also / Reference Information` block the Studio parses). Two things Nessus does not have are supplied by the connector: a stable plugin ID per compliance check in the Security Center range (Nessus reports every check of an audit under one plugin ID; the Studio identifies checks by plugin ID per host), and **First Discovered**, carried forward from the previous pull in the store so the Studio's due dates work.

## The service

`app.py` (FastAPI):

| Route | Purpose |
|---|---|
| `GET /` | the Studio with `<script src="connector.js">` injected before `</body>` (re-read when the file changes) |
| `GET /connector.js` | the panel |
| `GET /api/status` | connector, source, store, latest pull, running job, schedule, Studio version |
| `POST /api/pull`, `GET /api/jobs/{id}` | start a pull (one at a time), follow its progress |
| `GET /api/exports`, `/api/exports/{id}` | the pulls and a pull's manifest |
| `GET /api/exports/{id}/files/{name}` | an export file (`?download=1` for an attachment) |
| `GET /api/exports/{id}/risk-rules`, `/scans` | the audit data stored with the pull |
| `DELETE /api/exports/{id}` | remove a pull |
| `GET /api/tenable/check`, `/risk-rules`, `/scans` | live reads from Security Center |
| `GET/PUT /api/state/settings`, `/api/state/register` | shared report settings and risk register (optimistic concurrency on the register) |
| `GET /api/config` | the configuration in force, secrets masked |
| `GET /api/docs` | OpenAPI |

Everything but `/healthz` is behind HTTP basic authentication when `server.auth` is set; responses carry `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. File names and pull ids are validated against strict patterns, so the API cannot be used to read outside the store.

The scheduler is an asyncio task: next run from `weekday`, `time` and `timezone`, retry after `retry_minutes` when a scheduled pull fails, never two pulls at once.

## How the panel hooks into the Studio

`static/connector.js` is a classic script that runs after the Studio's own script and before `DOMContentLoaded`:

1. It removes its own `<script>` element first. The Studio captures `document.documentElement.outerHTML` at start-up (`SELF_SOURCE`) and uses it for the HTML report and the archive copy; without the removal every HTML report would carry a reference to the connector. The browser test checks that `SELF_SOURCE` and `buildHtmlReport()` contain no trace of it.
2. It adds the **Tenable** button and the empty-state hint, and the panel: status line (connector, source, last pull, schedule, Studio version), the pulls with their counts and download links, Pull now with progress, Check connection, the risk acceptances and the recent scans of the newest pull.
3. **Load** fetches the files of the selected pulls, wraps them as `File` objects with their export names and calls the Studio's `addFiles(files)`: from there on they are ordinary dropped exports (dating, "now" / history classification, de-duplication, archive "Source exports" folder, Excel source sheets).
4. It overrides three Studio functions, which are top-level function declarations and therefore writable globals: `riskLoadRegister` (read the register from `/api/state/register` first, fall back to IndexedDB, seed the server from a local register), `riskSaveRegister` (save locally, then PUT to the server, debounced; on a 409 take the server copy, merge the overrides, re-derive the states with `riskSync()` and save again) and `saveSettings` (save locally, then PUT). The overrides are installed while the page is still parsing, so the Studio's `init()` already goes through them. A 404 from the state API (shared state disabled) switches everything back to the Studio's own storage.

The Studio file itself is not modified for the integration; `tools/patch_studio.py` carries only the v4.7 fixes from the review.

## Store layout

```
data/
  2026-11-03/                     one folder per pull (a second pull the same day: 2026-11-03_HHMMSS)
    SC VA export 2026-11-03.csv.gz
    SC Compliance export 2026-11-03.csv.gz
    risk-rules.json               Accept Risk and Recast Risk rules at the time of the pull
    scans.json                    scan results of the last 45 days
    manifest.json                 status, counts, filters, source, timings, warnings, summary
  _state/
    settings.json                 shared report settings (with 20 history copies in history/)
    register.json                 shared risk register
```

## Design decisions

- **CSV with the export's column names, not a new JSON feed.** The Studio's parsing, QA and documentation are built around the export; a connector that produces the same files leaves that work untouched and keeps the Studio usable with hand-made exports.
- **Rows of two repositories are kept.** The Studio removes them and reports how many; that reconciliation with the Findings page is part of the report's credibility.
- **Inventory rows are added.** They cost little and make "Validate fixes" and the register's closures conclusive for hosts that were fully remediated.
- **Script injection at serve time, self-removed.** No fork of the 4 MB file for the integration; the HTML report and the archive copy stay plain Studio files.
- **Server-side state, with the browser as cache.** The register is precious and per-team; it is written to the server with a version check and kept with history copies; the local IndexedDB copy still works offline.
- **One pull at a time, in a thread.** A pull is minutes long and I/O bound; the API only reports progress.

## Limits

- The Studio still parses the files in the browser; a 113 MB compliance export takes the same time as before (review F5).
- Security Center field names for the newest columns (EPSS, Security End of Life, Host ID, Agent ID, risk-rule comments) could not be verified against a live system from this environment; the mapping lists candidates and `probe` reports what the real system returns. Adjust `export_schema.COLUMNS` if a column shows "(not in the record)".
- Nessus has no cumulative view: First Discovered is only as old as the connector's first Nessus pull.
- The `.nessus` parser uses the standard library XML parser; the files come from your own Nessus.
