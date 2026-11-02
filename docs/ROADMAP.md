# Roadmap

What exists now: the Studio v4.8 with the Tenable button, the lightweight Tenable Pull tool, the engine's tests, and the optional connector service. Ordered by value to the weekly process; none is started.

## Next

1. **First run against the real Security Center.** Decide where the file runs (`docs/TENABLE_PULL.md` §3), create the service account keys, pull, and send back `manifest.json`: its `mapping` shows which fields the real Security Center returned, so the few unverified column names (EPSS, Security End of Life, Host ID, Agent ID, rule comments) can be confirmed or corrected in `studio/src/tenable_pull.js`.
2. **Pull history in the tool.** Keep the last pulls' summaries and files in the browser (IndexedDB) so the previous export is one click away for the trend, Validate fixes and the register, without a Downloads folder.
3. **Self-hosted fonts** in the Studio and the tool (review F4), making both files genuinely offline.
4. **Worker-based parsing with progress** in the Studio (review F5) and, in the tool, streaming the CSV text straight into the Studio without the second copy in memory.

## Later

5. **Push risk overrides as Recast Risk rules** from the Studio's Risk tab (write access, confirmation step), so the register and Tenable never disagree.
6. **Internet-facing hosts from a Security Center asset list** instead of a hand-kept list.
7. **Mitigated source** (`sourceType: patched`) for fix dates and the "fixed within timeline" rate.
8. **Scheduled pulls without a person**: the optional connector, or a scheduled task that runs the Studio headless on a workstation.
9. **Source parts of the Studio in the repository** and the QA scripts next to them, so every change is a diff.
10. **Tenable Vulnerability Management (cloud)** as a third source; the export schema is the integration point.
