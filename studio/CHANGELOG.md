# Tenable Report Studio — changelog

## 4.8 (2 Nov 2026)

Built by `tools/build_tenable.py`: the Tenable Pull engine and panel are inlined before `</body>` (markers `trs-tenable:start/end`, replaced on every build); no other line of the Studio changed.

- **Tenable** button (and "Load from Tenable" on the empty state): pulls the exports straight from Security Center (REST API, API keys or session login) or Nessus (port 8834) with one paced request at a time and loads them through the Studio's own file path, exactly like dropped exports. Options: severities, inventory rows, compliance, repositories or scans, pacing and page sizes, a previous export for Nessus first-seen dates.
- Receives the files sent by `Tenable_Pull.html` ("Open the Studio and load these files") from the window that opened it.
- The HTML report and the archive copy carry the panel code; it is inert in the report (report mode).
- 5 Nov: Source defaults to "Detect automatically"; every field explained in the panel; after a failed connection a diagnosis says whether the server answered (CORS) or nothing connected, probing the usual ports.
- 5 Nov: **browser add-on** (`tools/build_extension.py`): the Studio and Tenable Pull packaged as a Chrome / Edge extension so that they may call Security Center from the browser, which a page opened from a folder cannot (CORS). The Studio's scripts are split into files for the extension CSP; the single-file Studio ships inside and is used for the HTML report and the archive copy, which stay self-contained.

## 4.7 (2 Nov 2026)

Applied with `tools/patch_studio.py` (exact replacements, verifiable with `--check`); findings from `docs/REVIEW.md`.

- Load notice: file names and error text are HTML-escaped (a crafted file name could run script in the Studio).
- Vulnerabilities tab and Risk tab: the CVE list under a vulnerability name is escaped like the rest of the table.
- Compliance tab: the "See also" references of a check keep their line breaks.
- No change to the Excel workbooks, the PDF, the HTML report, the validation workbook or the risk tracker.

Works unchanged from a folder; served by the connector it gains the Tenable panel (loaded at run time, never part of the file or of the HTML reports it produces).

## 4.6 (29–31 Oct 2026)

As delivered: Validate fixes (baseline export against the new one, one marked list of the old vulnerabilities and failed checks, validation workbook), Risk tab (inherent → compensating controls → residual, editable formula, register in the browser, risk tracker workbook), archive additions. See `docs/PROJECT_NOTES.md` for the history and the QA.
