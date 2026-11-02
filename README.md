# Tenable Report Studio

Weekly vulnerability-assessment and CIS-compliance reporting for ALTANFEETHI from Tenable Security Center, with nothing to install: two HTML files.

- **Tenable Pull** (`studio/Tenable_Pull.html`): the lightweight tool. Enter the endpoint and the service account's API keys, check the connection, pull. It fetches the vulnerability rows (Critical to Low, plus the inventory rows that keep hosts without findings listed), the compliance rows, the Accept/Recast Risk rules and the recent scans straight from the Security Center REST API (or from Nessus on port 8834), one paced request at a time, and produces the two CSV files in the Security Center export layout. Download them, or "Open the Studio and load these files".
- **The Studio** (`studio/ALTANFEETHI_Tenable_Report_Studio.html`, v4.8): the report tool (Excel workbooks, PDF, HTML report, Validate fixes, risk register), now with a **Tenable** button that does the same pull inside the Studio and loads the files directly.
- Optional, not needed for the above: `connector/`, a small service for scheduled pulls (see `connector/`).

| Tenable Pull | After the pull | The Studio's Tenable button |
|---|---|---|
| ![Tenable Pull](docs/img/tenable-pull.png) | ![Result](docs/img/tenable-pull-result.png) | ![Studio](docs/img/studio-tenable.png) |

## Use

1. Create API keys for a read-only Security Center user (Users → the user → Generate API Keys; API keys must be allowed under Settings → Configuration → Security). Nessus: My Account → API Keys.
2. Open `Tenable_Pull.html` (or the Studio and click **Tenable**), enter the endpoint and the keys, **Check connection**, **Pull**.
3. Load the files into the Studio (one click from the tool, or drop the CSVs) and build the report as usual.

**One thing to decide first: where the file runs.** A page may only read another server's answers when that server allows it (CORS), and Security Center and Nessus do not by default; the tool tells you precisely when that is the case. The options, in order of preference: serve the two HTML files from the Security Center web root (same origin, nothing to allow), add the CORS headers to the Security Center Apache configuration, or use a dedicated browser profile for this tool only. `docs/TENABLE_PULL.md` has the exact steps.

**Not breaking Security Center.** Every analysis page is a database query, so the tool sends one request at a time, waits between requests (Gentle 2 s, Normal 0.75 s, Fast 0.15 s), uses moderate pages (1,000 / 500 rows), times a request out after 2 minutes and backs off on 429 / 503 (honouring Retry-After). The result shows the request count and the time the server spent. The same pacing is built into the optional connector.

## Repository layout

| Path | What |
|---|---|
| `studio/Tenable_Pull.html` | the lightweight tool (built) |
| `studio/ALTANFEETHI_Tenable_Report_Studio.html` | the Studio v4.8 (built: v4.7 fixes plus the Tenable panel) |
| `studio/src/` | the engine (`tenable_pull.js`), the tool's page template, the Studio panel glue, the engine's unit tests |
| `tools/build_tenable.py` | builds both HTML files from `studio/src/`; `--check` verifies them |
| `tools/patch_studio.py` | the v4.7 fixes to the Studio as exact, verifiable patches |
| `docs/TENABLE_PULL.md` | set-up, where to run the file, pacing, troubleshooting |
| `docs/REVIEW.md` | the application review of v4.6: architecture, strengths, findings, recommendations |
| `docs/ARCHITECTURE.md` | how the pull works and how it hooks into the Studio |
| `docs/ROADMAP.md` | what comes next |
| `docs/PROJECT_NOTES.md` | the running notes delivered with the Studio (history, decisions, QA) |
| `connector/` | optional service for scheduled pulls, with its own README, `DEPLOYMENT.md` and tests |

## Tests

```bash
node --test studio/src/tenable_pull.test.mjs             # the engine: CSV, dates, ids, pacing and retries with a fake fetch
cd connector && pip install -e .[test] && pytest        # 25 tests, including the browser runs
```

The browser tests open `Tenable_Pull.html` from a folder in Chromium against a synthetic Security Center that allows the page (CORS) and refuses every 7th analysis request with HTTP 429: the pull completes with the figures an independent recount predicts, the files are handed over to the Studio, the Studio's own Tenable button pulls and loads, and a server that does not allow the page produces the explanatory message.

## Changing the tool

Edit `studio/src/tenable_pull.js` (engine and shared panel), `studio/src/Tenable_Pull.template.html` (the standalone page) or `studio/src/studio_panel.js` (the Studio button), then `python3 tools/build_tenable.py`. The Studio keeps its own code untouched apart from the v4.7 fixes; the panel is an inline block before `</body>` that the build replaces.
