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

### The Mitigation tab and the data folder (`studio/src/mitigation.js`)

A third block in the same marker section. It wraps three Studio functions (writable globals): `riskSync`, to add a history row per pull to the register and to save the data folder after every sync; `renderAll`, to render the tab; `archiveFiles`, to add the mitigation tracker and `findings-register.csv` to the Archive. All figures derive from the register (`RISK_REG.items`: first seen, last seen, status, closed on, reopened, host presence) joined with the live findings for due dates; nothing is stored twice. The data folder is a `FileSystemDirectoryHandle` kept in the Studio's IndexedDB store (`dataDir`), with `pulls/<scan date>/` (every loaded export file, `manifest.json` and `risk-rules.json` from the last Tenable pull), `register/` (the register as JSON and CSV, the history) and `reports/` (set as the Archive's remembered folder). Writes are debounced after a sync; reads list the pulls and load their files through `addFiles`, and take the folder's register when it is newer than the browser's. The export files are named by their scan date (the 95th percentile of Last Observed, the Studio's own dating), so pulls of different scans never share a name. Details for users: `docs/MITIGATION.md`.

### The two builds (`tools/build_tenable.py`)

- `Tenable_Pull.html` = the page template with the engine inlined.
- The Studio = the Studio file with `<!-- trs-tenable:start -->` … `<!-- trs-tenable:end -->` inserted before `</body>`: the engine and `studio_panel.js`, which adds the **Tenable** button, mounts the panel in the Studio's modal host and loads the result through `addFiles()`; it also posts `trs-ready` to `window.opener` and accepts `trs-files` messages from that opener only. The block is replaced on every build; the Studio's own code is untouched apart from the v4.7 fixes applied by `tools/patch_studio.py`. The Studio captures its own source at start-up for the HTML report and the archive copy, so both carry the block; it is inert in report mode.

### CORS, and the add-on

`fetch()` from a page to Security Center is a cross-origin request. The browser sends it (with a preflight `OPTIONS` because of the `X-APIKey` and `Content-Type` headers) but only lets the page read the answer if the server allows the page's origin, which Security Center does not. After a failure the tool runs a no-cors probe: a response, even unreadable, proves the server is there and only CORS is in the way; no response means the certificate or the address, and the usual ports are probed on the host.

The answer for daily use is the **browser add-on** (`studio/extension-src/`, `tools/build_extension.py`): a Manifest V3 extension whose pages are the Studio and Tenable Pull. Extension pages may call the hosts under `host_permissions` without CORS, so nothing changes on the server. The extension CSP forbids inline scripts, so the build writes each inline `<script>` of the built Studio to a file (`studio-NN.js`) and references it; the single-file Studio ships inside as `studio.single.html`, and `extension_glue.js` puts it back into `SELF_SOURCE` after start-up so the HTML report and the archive copy remain self-contained files. pdfmake and ExcelJS only reach `Function()` in guarded global-object fallbacks, so they run under the CSP; the test builds a PDF and a workbook inside the add-on to prove it. The other options (serve the files from the Security Center web root, CORS headers in Apache, a dedicated browser profile, the connector) are in `docs/TENABLE_PULL.md` §3; nothing in the engine depends on which is chosen.

### Tests

- `node --test studio/src/tenable_pull.test.mjs`: CSV quoting and parsing, dates, record-to-row, de-duplication, crc32 parity, scan selection, the transport (one in flight, pacing, 429 with Retry-After, retries exhausted) and the client errors with a fake `fetch`.
- `connector/tests/test_pull_tool.py` (Playwright): `Tenable_Pull.html` from `file://` against the mock Security Center with CORS enabled and every 7th analysis request refused with 429; counts against an independent recount; hand-over to the Studio pop-up; the Studio's own Tenable button; the explanation when the server does not allow the page.

## 2. The optional connector service

`connector/` is the same pull done server-side (Python, `trs_connector`): a weekly schedule, a dated store with the risk rules and scan results of each pull, the Studio served on port 8000 with a panel that loads a pull, shared report settings and risk register. Its client has the same pacing (`Pacer`: one request at a time, `request_interval`, retries with backoff and `Retry-After`). Details: `connector/README.md`, `connector/DEPLOYMENT.md`, `connector/ARCHITECTURE.md`.
