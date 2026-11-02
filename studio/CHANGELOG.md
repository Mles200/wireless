# Tenable Report Studio — changelog

## 4.7 (2 Nov 2026)

Applied with `tools/patch_studio.py` (exact replacements, verifiable with `--check`); findings from `docs/REVIEW.md`.

- Load notice: file names and error text are HTML-escaped (a crafted file name could run script in the Studio).
- Vulnerabilities tab and Risk tab: the CVE list under a vulnerability name is escaped like the rest of the table.
- Compliance tab: the "See also" references of a check keep their line breaks.
- No change to the Excel workbooks, the PDF, the HTML report, the validation workbook or the risk tracker.

Works unchanged from a folder; served by the connector it gains the Tenable panel (loaded at run time, never part of the file or of the HTML reports it produces).

## 4.6 (29–31 Oct 2026)

As delivered: Validate fixes (baseline export against the new one, one marked list of the old vulnerabilities and failed checks, validation workbook), Risk tab (inherent → compensating controls → residual, editable formula, register in the browser, risk tracker workbook), archive additions. See `docs/PROJECT_NOTES.md` for the history and the QA.
