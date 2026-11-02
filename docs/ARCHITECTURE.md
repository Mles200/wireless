# Architecture

Two ways to get Tenable data into the Studio, sharing one export layout:

```
                 ┌──────────────── Tenable Pull (HTML file, or the Studio's Tenable button) ──────────────┐
 browser on the  │  endpoint + API keys ──fetch()──▶ Security Center :443 /rest/…  (or Nessus :8834)        │
 workstation     │  one request at a time, paced   ◀── JSON pages ──                                           │
                 │  rows ──▶ CSV files in the Security Center export layout ──▶ the Studio (addFiles)         │
                 └───────────────────────────────────────────────────────────────────────────────────────────┘

 optional        ┌──────────────── connector service (Python, on the Tenable VM) ─────────────────────────────┐
                 │  weekly schedule ──▶ the same pull server-side ──▶ dated store ──▶ Studio served on :8000  │
                 └───────────────────────────────────────────────────────────────────────────────────────────┘
```

## 1. The browser-side pull

### The engine (`studio/src/tenable_pull.js`)

One file, loadable in a page or in Node, with five parts:

1. **Transport.** Every request goes through one chain, so concurrency is always 1; a request starts at least `interval` ms after the previous one ended; `AbortController` cancels it after `timeout` ms; 429 / 502 / 503 / 504 and timeouts are retried with exponential backoff (2 s, 4 s, 8 s… capped at 60 s, with jitter) or the server's `Retry-After`, up to `retries` times; a safety limit stops a pull after 20,000 requests. Three presets (Gentle, Normal, Fast) set interval, retries, timeout and page sizes; the stats (requests, paused, busy, slowest, retries) are shown after the pull and written to the manifest.
2. **Clients.** `SecurityCenter` (API keys as `X-APIKey: accessKey=…; secretKey=…`, or a session token from `/rest/token`; the JSON envelope's `error_code` becomes an error; a filter the installed version rejects, error 146, is dropped with a warning and the page retried) and `Nessus` (`X-ApiKeys`, scan list, `.nessus` export with a status poll no faster than every 3 s).
3. **Schema.** The 46 columns of the Security Center "Vulnerability Detail List" export with the header names the Studio's alias table accepts, each mapped to candidate field names of a `vulndetails` record; dates as ISO 8601 UTC; routing by nature (compliance plugin or not); de-duplication by plugin, host, port, protocol, repository (and check name for compliance). The mapping actually used is recorded in the manifest so an unverified field name shows up as a named gap, not as silent blanks.
4. **Pulls.** `pullSecurityCenter`: three queries (vulnerabilities, inventory Info rows of five plugins, compliance), then the risk rules and the recent scans. `pullNessus`: selected completed scans, parsed with `DOMParser`, compliance checks given stable plugin IDs in the Security Center range (`1,000,000 + crc32(audit|name) mod 99,000,000`, identical to the Python connector), First Discovered carried forward from a previous export's rows.
5. **The panel.** `mount(container, {mode})` renders the form (source, endpoint, keys, options, pacing), Check connection, Pull, the result table with downloads, the risk acceptances and scans, and in standalone mode "Open the Studio and load these files". Settings persist in `localStorage` under `trs.tenable`; the secret key stays in `sessionStorage` unless "Remember" is ticked.

### The two builds (`tools/build_tenable.py`)

- `Tenable_Pull.html` = the page template with the engine inlined.
- The Studio = the Studio file with `<!-- trs-tenable:start -->` … `<!-- trs-tenable:end -->` inserted before `</body>`: the engine and `studio_panel.js`, which adds the **Tenable** button, mounts the panel in the Studio's modal host and loads the result through `addFiles()`; it also posts `trs-ready` to `window.opener` and accepts `trs-files` messages from that opener only. The block is replaced on every build; the Studio's own code is untouched apart from the v4.7 fixes applied by `tools/patch_studio.py`. The Studio captures its own source at start-up for the HTML report and the archive copy, so both carry the block; it is inert in report mode.

### CORS, the deployment decision

`fetch()` from a page to Security Center is a cross-origin request. The browser sends it (with a preflight `OPTIONS` because of the `X-APIKey` and `Content-Type` headers) but only lets the page read the answer if the server allows the page's origin. The tool detects the failure and names the options (serve the file from the Security Center web root, add the headers in Apache, a dedicated browser profile, or the connector); see `docs/TENABLE_PULL.md` §3. Nothing in the engine depends on which option is chosen.

### Tests

- `node --test studio/src/tenable_pull.test.mjs`: CSV quoting and parsing, dates, record-to-row, de-duplication, crc32 parity, scan selection, the transport (one in flight, pacing, 429 with Retry-After, retries exhausted) and the client errors with a fake `fetch`.
- `connector/tests/test_pull_tool.py` (Playwright): `Tenable_Pull.html` from `file://` against the mock Security Center with CORS enabled and every 7th analysis request refused with 429; counts against an independent recount; hand-over to the Studio pop-up; the Studio's own Tenable button; the explanation when the server does not allow the page.

## 2. The optional connector service

`connector/` is the same pull done server-side (Python, `trs_connector`): a weekly schedule, a dated store with the risk rules and scan results of each pull, the Studio served on port 8000 with a panel that loads a pull, shared report settings and risk register. Its client has the same pacing (`Pacer`: one request at a time, `request_interval`, retries with backoff and `Retry-After`). Details: `connector/README.md`, `connector/DEPLOYMENT.md`, `connector/ARCHITECTURE.md`.
