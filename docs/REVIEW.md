# Tenable Report Studio v4.6 — application review

Reviewed: `ALTANFEETHI_Tenable_Report_Studio.html` version 4.6 (31 Oct 2026, 4,047,307 bytes) together with the project notes (`docs/PROJECT_NOTES.md`). Line numbers below refer to the application script inside that file (the last `<script>` block, lines 500–2919 of the HTML; "app line N" = HTML line 500 + N).

## 1. Summary

The Studio is a single-file browser application that turns Security Center exports into the weekly report (Excel, PDF, HTML), validates fixes between two exports and tracks a residual-risk register. It is well built for what it is: the data model is faithful to Tenable (plugin IDs, raw plugin output, repository-aware de-duplication), the output quality work (Excel sanitising, strict XML checks, pdfmake rules) is thorough, and the in-product Guide keeps definitions in one place.

Its limits come from the delivery model rather than the code: everything depends on a person exporting the right CSVs with the right columns each week, the 113 MB compliance file is parsed on the browser's main thread, settings and the risk register live in one browser profile, and nothing records what was accepted in Tenable. Five small code defects were found; four are fixed in v4.7 (this repository), one is a recommendation.

The "next level" built in this repository, the connector, addresses the delivery model: it pulls the same data from Security Center (or Nessus) on a schedule, keeps every pull with its audit data, serves the Studio with a Tenable panel, and makes settings and the register shared.

## 2. Architecture and data flow

| Part | Size | Notes |
|---|---|---|
| Vendor libraries (PapaParse 5.4.1, SheetJS, Chart.js 4.4.1, pdfmake 0.2.20 with embedded IBM Plex fonts, ExcelJS 4.4.0) | ~3.3 MB | inline, unmodified |
| Application script | 339 KB, 2,418 lines | one classic script, top-level functions and `const` state; sections: defaults, state, helpers, parsing, segmentation, loading, aggregation, charts, rendering per tab, report, Excel, HTML report, settings, PDF, archive, validation, risk |
| Markup and CSS | 25 KB | light/dark theme with CSS variables |

Pipeline for a loaded file (app lines 213–470):

1. `readFile` parses CSV (PapaParse, header row) or xlsx (SheetJS, all sheets with a Plugin column).
2. `normalise` maps columns through the alias table `COLS` (app line 73), skips rows without a numeric plugin ID or a valid IPv4, routes Info rows of non-compliance plugins to the inventory, compliance plugins (ID ≥ 1,000,000, family "compliance" or an `auditFile` cross reference) to checks, everything else to findings. `finishFinding` derives KEV, EoL, theme, product family, attack vector and priority; `finishCheck` parses Result, Actual Value, Policy Value, Information, Solution, Impact, See Also and Reference Information out of the plugin output.
3. `addFiles` dates each file at the 95th percentile of its Last Observed values; `classifyFiles` calls files within 3 days of the newest "current", older ones "previous" (history).
4. `rebuild` merges the current files, newest first, removing duplicates by `plugin|ip|port|protocol` (the rows stored in two repositories) and records the reconciliation figures; previous files become trend snapshots.
5. `buildHosts` applies the segmentation rules (hostname regexes first, then CIDRs), the site inference, the internet-facing list, the SLA due dates and the host risk score; `consolidate` and `productsOf` build the per-vulnerability and per-remediation-action views.
6. Rendering is per tab from the global `state`; the PDF, the two Excel workbooks, the HTML report (the Studio's own source with the data embedded as JSON), the validation workbook and the risk tracker are generated client-side.

Persistence: report settings in `localStorage` (`trs.settings`, `trs.logo`), the archive folder handle and the risk register in IndexedDB (`trs-studio`), both keyed by the page origin.

## 3. What is good

- **Fidelity to Tenable.** Identifiers are plugin IDs only; evidence is the raw plugin output; the repository de-duplication reproduces the reconciliation with the Findings page documented in the notes (1,760 vs 2,256 Critical on 20 Oct).
- **Output engineering.** Every Excel cell goes through one sanitiser (`xs`: control characters, 32,000-character cap, NaN, invalid dates); the 26 Oct frozen-pane repair prompt was root-caused and prevented; pdfmake pitfalls (zebra fills over nested tables, unbreakable tokens, footer nodes in `pageBreakBefore`) are handled explicitly.
- **One source of definitions.** `GUIDE` feeds the Guide tab, the Excel "How to read" sheet and the PDF definitions, so the three cannot drift.
- **Escaping discipline.** User- and data-derived text goes through `esc()` almost everywhere, `linkify` escapes before linking, links open with `rel="noopener"`.
- **Reproducibility.** The archive stores the source exports, the settings and a copy of the tool version that produced the run.
- **Explicit models.** The validation statuses and the risk formula are documented in the product (dialog text, Model sheet) and every number is editable; the defaults are calibrated and the calibration is recorded in the notes.

## 4. Findings

Severity reflects impact on a team using the Studio as delivered (opened from a folder in Chrome or Edge).

### F1 — Medium — File names and error text rendered as HTML in the load notice (fixed in 4.7)

`addFiles` collects error messages that embed the file name (`${fileName}: this does not look like a Tenable export…`, app lines 247, 412, 416) and shows them with `showNotice(errors.join('<br>'), 'bad')` (app line 426), which assigns `innerHTML`. A file named `<img src=x onerror="…">.csv` dropped on the Studio runs script in the Studio's origin: it can read the settings, the IndexedDB risk register and the remembered archive folder handle, and alter the report. Exploitation needs someone to hand the analyst a crafted export, which is plausible for a tool that receives files from several people. Fix: `errors.map(esc)`. Applied.

### F2 — Low — CVE identifiers inserted without escaping (fixed in 4.7)

Two tables build the CVE line without `esc`: the consolidated vulnerability table (app line 793, `[...c.cve].slice(0,3).join(', ')`) and the risk table (app line 2275). The values come from the Tenable CVE column, so an exploit requires malicious data in Security Center; low likelihood, but inconsistent with the rest of the code. Fix: wrap in `esc`. Applied.

### F3 — Low — "See also" of a CIS check loses its line breaks (fixed in 4.7)

`renderCmp` renders `linkify(c.seeAlso)` without the `.replace(/\n/g,'<br>')` used in `solutionBlock`, so multi-line references of a check run together. Cosmetic. Applied.

### F4 — Medium — "Runs offline, nothing leaves the browser" is not entirely true (recommendation)

The `<head>` loads `https://fonts.googleapis.com/css2?family=IBM+Plex+Sans…` (HTML line 6). Every opening of the Studio, and of every HTML report sent to system owners, makes a request to Google (fonts.googleapis.com, then fonts.gstatic.com) that discloses the client IP and, when served over HTTP, the referrer. Offline the page renders with the fallback fonts after the request fails. The IBM Plex TTF files are already embedded for the PDF (`PDF_FONTS`, ~300 KB base64) and could serve the page through `@font-face` with data URLs, which would make the file genuinely offline at no size cost. Not changed in 4.7 because it alters the rendering and needs the owner's sign-off; the connector serves the page with `Referrer-Policy: no-referrer` in the meantime.

### F5 — Medium — The 113 MB compliance export is parsed on the main thread (recommendation)

`readFile` calls `Papa.parse(file, {worker:false})` (app line 227) and keeps every row object; `readRaw` parses the whole file a second time when the Excel is built (app line 937). For the 28 Oct compliance file (113 MB, 33,280 rows) this freezes the page for the duration of the parse, shows no progress, and holds several copies of the data in memory. Recommendation: PapaParse worker mode or streaming (`step`), a progress notice, and keeping only the columns the Studio uses from the raw re-read. The connector does not change the parse, but it removes the Excel-origin case (xlsx exports are far slower to read) and serves the files compressed.

### F6 — Medium — Export dating and "current" detection are heuristics (mitigated by the connector)

The export date is the 95th percentile of Last Observed (app line 420) and "current" means within 3 days of the newest file (app line 433). Two exports of the same scan date are merged silently (the notes record this for 20 and 25 Oct); agent results that report a stale Last Observed can shift the date. With the connector every file comes from one dated pull, the pull folder is the date, and the panel loads a pull as a unit.

### F7 — Medium — The risk register and the settings live in one browser profile (mitigated by the connector)

Closures, reopen counts and overrides are kept in IndexedDB of the profile that loaded the export (app lines 2193–2215); a cleared profile, a new laptop or a colleague's browser starts from nothing unless `risk-register.json` was exported and dropped back in. Settings behave the same (`localStorage`). The Studio documents the export, but the process relies on discipline. The connector keeps both on the server (`/api/state/settings`, `/api/state/register`, with history copies) and the hosted Studio reads and writes them, with a conflict check on the register.

### F8 — Low — `file://` origin shares storage with every other local page

In Chromium all `file://` documents form one origin: any other HTML file opened locally can read or overwrite `trs.settings` and the Studio's IndexedDB database. Serving the Studio from the connector gives it its own origin.

### F9 — Low — Date parsing depends on the engine's `Date.parse` for non-ISO strings

`parseDate` (app line 169) falls back to `Date.parse` for strings such as "Oct 25, 2026 06:12:33 UTC"; this works in Chromium and Firefox but is implementation-defined, and `dd/mm/yyyy` strings from an Excel-origin export would be read as `mm/dd`. The connector writes ISO 8601 UTC (`2026-10-25T06:12:33Z`), which is the one format the ECMAScript specification guarantees.

### F10 — Low — Accept and Recast Risk decisions leave no trace in the report (addressed by the connector)

Findings accepted in Security Center drop out of the default export and therefore out of the report; a reader cannot tell "fixed" from "accepted" and an auditor has no list of the acceptances. The connector stores the Accept Risk and Recast Risk rules at every pull and the panel shows them (plugin, hosts, comment, expiry, author).

### F11 — Low — Host presence for closures depends on Info rows that the recommended VA export does not include

`riskSync` closes a finding when the host is still "present" (any finding, check or inventory row, app line 2203) and "Validate fixes" counts a host as absent otherwise. The recommended VA export (Critical to Low) carries no Info rows, so a host that was fully remediated and has no CIS checks disappears and its findings are never closed (the notes flag this). The connector adds the Info rows of the five inventory plugins (OS identification, hostname, scan information, CPE, patch assessment) so such hosts stay listed as "scanned, no findings".

### F12 — Info — Maintainability

One 339 KB script with lines of up to 2,000 characters, global functions and a global `state` object, built by hand from parts that are not in the repository (the notes mention `part2_core.js`, `part4b_excel.js`, `test/qa.py`). The code is readable and consistently commented, but a change is hard to review and the delivered file is the only source. Recommendation: commit the source parts and the build step, keep this repository as the home of the Studio (this is done here for the single file plus a patch script that applies the 4.7 changes verifiably), and keep the QA script with it.

### F13 — Info — Modals and focus

`Escape` closes the host drawer but not the settings, archive, validation or risk dialogs; focus is not trapped or returned. Minor for a desktop tool.

## 5. Verification against the project notes

- Version markers of 4.6 are present: `GUIDE.validate` and `GUIDE.risk`, the validation workbook sheets (Old vulnerabilities, Old vulnerabilities by host, Old failed checks, By remediation action, Hosts), the risk model v2 (`DEFAULT_RISK`: weights start 1 / KEV 3 / exploit 2 / EPSS 1 at 30 % / VPR 1 at 7 / network 1 / internet 1; severity adjustment +1/0/−1/−2; thresholds 16/10/4; controls 40/40/40/20/20; cap 60 %; KEV floor High), the register in IndexedDB key `riskRegister`, the Archive checkbox for the risk tracker. All match the notes.
- The column alias table covers every column the notes list for the export (VPR, EPSS, See Also, CPE, Exploit Frameworks, Security End of Life Date, Family, NetBIOS, Steps to Remediate, Host ID, Agent ID, Check Type, Accept/Recast Risk Comment).
- The de-duplication key, the inventory plugin list (11936, 55472, 19506, 45590, 209654), the SLA table and the priority rules are as documented.

## 6. Recommendations, in order

1. Run the Studio from the connector (this repository): scheduled pulls with the inventory rows, shared settings and register, risk-rule audit trail, no manual export. See `docs/DEPLOYMENT.md`.
2. Adopt v4.7 (F1–F3) and keep the Studio file under version control here; apply future changes through `tools/patch_studio.py` or by committing the source parts.
3. Self-host the fonts from the embedded TTFs or drop the Google Fonts link (F4).
4. Move CSV parsing to a worker with a progress notice (F5); consider dropping the raw re-read for the source sheets in favour of the connector's download links.
5. Keep `test/qa.py` and `test/xlsx_strict.py` with the Studio in this repository and run them on 4.7 with the 25 Oct exports (the notes say the 4.6 run was done without the test folder).
6. Procedure: the SVA procedure clause on residual-risk timelines (notes) and a line stating that accept/recast decisions are listed in the connector's risk-rule record.

## 7. Changes made in v4.7

Applied by `tools/patch_studio.py` (each an exact, verified replacement; `--check` confirms them):

1. `STUDIO_VERSION` 4.6 → 4.7.
2. Load notice: `errors.map(esc)` (F1).
3. CVE line in the Vulnerabilities tab escaped (F2).
4. CVE line in the Risk tab escaped (F2).
5. CIS "See also" keeps its line breaks (F3).

No output path, workbook, PDF or HTML report content changed; the browser test in `connector/tests/test_browser.py` loads a synthetic pull through the panel and checks the figures the Studio shows against an independent recount, the Risk tab and the HTML report builder.
