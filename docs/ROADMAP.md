# Roadmap

What exists now: the Studio v4.7 and the connector v0.1 (scheduled pulls from Security Center or Nessus, Studio-ready exports with the audit data, the hosted Studio with the Tenable panel, shared settings and register, tests). The items below are ordered by value to the weekly process; none is started.

## Phase 2 — automate the report itself

1. **Server-side report generation.** The Studio builds the Excel, the PDF and the HTML report in the browser; the connector can drive the hosted Studio headless (Playwright is already used by the tests) right after the weekly pull and drop the outputs and an archive folder next to the pull. The Monday report would be waiting in the store, and could be e-mailed or posted to Teams.
2. **Pull notifications.** A message (e-mail / Teams webhook) when a scheduled pull fails or when the export counts move more than a threshold against the previous pull (a repository that stopped syncing, a scan that did not run).
3. **Trend across every pull.** The Studio compares the loaded exports; the connector holds all of them. A trend endpoint (open findings by severity per pull, hosts seen, new and fixed) and a small chart in the panel would give the quarter view without loading twelve files.

## Phase 3 — close the loop with Security Center

4. **Push risk overrides as Recast Risk rules.** An override in the Risk tab could create the corresponding Recast Risk rule in Security Center (with the note as the comment), so the register and Tenable never disagree. Needs a write-capable API key and a confirmation step; M ruled on 22 Oct that decisions live in Tenable, which this respects.
5. **Internet-facing hosts from an asset list.** Fill the Studio's "Internet-facing hosts" from a Security Center asset list (`/rest/asset`) instead of a hand-kept list.
6. **Mitigated source.** Read the `patched` source (Tenable's own Mitigated view) at every pull, for fix dates and the "fixed within timeline" rate the notes mention as a possible ask.

## Phase 4 — the Studio

7. **Worker-based parsing with progress** (review F5) and no second read of the raw file for the Excel source sheets.
8. **Self-hosted fonts** from the embedded TTFs (review F4), making the file genuinely offline.
9. **Source parts in the repository** and the QA scripts (`test/qa.py`, `test/xlsx_strict.py`) next to them, so a change is a diff, not a 4 MB file.
10. **Keyboard and focus handling** of the dialogs (review F13).

## Platform

11. **Authentication:** LDAP / SSO in front of the connector (reverse proxy with the corporate IdP) instead of one shared basic-auth password; per-user attribution of register changes.
12. **Tenable Vulnerability Management (cloud)** as a third source if the estate moves; the export schema is already the integration point.
13. **Packaging:** a container image and a Windows service wrapper, for sites without a Linux VM.
