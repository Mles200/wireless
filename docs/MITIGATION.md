# The Mitigation tab and the data folder

Studio 4.9 adds a **Mitigation** tab (between Risk and Report) and a **data folder** on your computer. Together they answer the weekly questions: what got mitigated, what is still pending, what is new, what is in the environment, and how it moves from pull to pull; and they keep every pull and the register as plain files you can open, reference and back up.

## 1. Where the figures come from

The Studio keeps a **register**: one entry per finding ever seen (a vulnerability on a host, plugin ID and IP). Every time a pull is loaded the register is brought in line with it:

| Event | Rule |
|---|---|
| Open | the finding is reported in the newest pull |
| Mitigated (closed) | the finding is no longer reported **and its host is still in the pull** (any finding, check or inventory row). The closed date is the pull date. |
| Not verified | the finding was open and its host is absent from the newest pull: it is neither open nor closed until the host is scanned again |
| New | first seen after the previous pull (what the very first pull saw is the baseline, never "new") |
| Reopened | closed before, reported again |

The first-seen date comes from Security Center (First Discovered), so the days a finding stayed open and whether it was closed within the Tenable timeline (Settings, remediation timelines) are exact even for findings older than the register. The register also carries the per-pull **history**: open findings by severity at each pull, mitigated, new, reopened, hosts scanned, hosts absent.

The inventory rows the pull adds (OS identification, hostname, scan information) are what make "mitigated" reliable: a host that was fully remediated still appears in the pull as "scanned, no findings", so its last findings close instead of becoming "not verified".

## 2. The tab

- **Period** (toolbar): mitigated since the previous pull, in the last 30 or 90 days, or since tracking began. The severity chips, the search box and the scope bar (environment, site, system) filter everything below.
- **KPIs**: pending (open now) by severity, mitigated in the period, new, reopened, overdue (open past the Tenable due date), hosts in the environment (with the clean ones and the new ones), not verified (with the number of absent hosts), mitigated ever.
- **Open findings per pull** and **Mitigated and new per pull**: the history as charts.
- **Remediation actions**: one row per product or update family, with Done / In progress / Not started, open, not verified, mitigated in the period, closed ever, % done (closed of everything ever seen), oldest open, due, overdue and the hosts still open.
- **Mitigated**: by vulnerability, with the hosts fixed, the latest closed date, the average days to fix and the share closed within the timeline; click a vulnerability for the per-host rows.
- **Pending**: by vulnerability, oldest first seen first, with the earliest due date, the overdue and new counts; click for the hosts.
- **Environment**: hosts of the pull by environment (with findings, clean, new), open, mitigated, not verified. **Hosts not in this pull**: their last sight and open findings.
- **Data folder** (bottom): the folder, the pulls stored there with a **Load** button each, Save now, Change folder, Download data ZIP.
- **Excel**: the mitigation tracker (Summary, Mitigation tracker with one row per finding ever seen, Pending, Mitigated, Remediation actions, Environment, Pull history). The Archive includes it as well, together with `findings-register.csv`.
- **Update from Tenable**: opens the Tenable panel; after the pull the register, the history and the data folder are updated.

An older pull loaded on its own does not move the register (a notice says so); load the newest pull to update.

## 3. The data folder

Choose it once: Mitigation tab → **Choose folder** → for example a new folder `Tenable Data` on the Desktop. The browser remembers it; on a new session it may ask you once to allow access again (an **Allow access** button appears in the tab). From then on every pull and every change of the register are written there automatically:

```
Tenable Data/
  README.txt                        what is what
  pulls/
    2026-11-08/
      SC VA export 2026-11-08.csv       the exports exactly as loaded into the Studio
      SC Compliance export 2026-11-08.csv
      manifest.json                     counts, filters, which Security Center field each column came from, load figures
      risk-rules.json                   the Accept / Recast Risk rules at the time of the pull
    2026-11-01/ …                       every pull, including exports loaded by hand
  register/
    findings-register.json            every finding ever seen with its dates, status, risk values and overrides
    findings-register.csv             the same as a flat table (open it in Excel)
    history.json, history.csv         one row per pull
  reports/                            the Archive button saves its runs here from now on
```

- **Reference**: the CSVs open in Excel; `findings-register.csv` has one row per finding with Status, Severity, Plugin ID, Vulnerability, Remediation action, Host, IP, Environment, Site, First seen, Last seen, Closed on, Reopened, In newest pull, Residual risk, Inherent risk, CVE.
- **Load an earlier pull**: the Data folder panel lists the pulls; **Load** puts one into the Studio next to what is loaded (the newest becomes "now", older ones history for the trend and Validate fixes).
- **Restore on another computer**: drop `findings-register.json` on the Studio (or choose the same folder: the Studio takes the newer register of the two).
- **Without the folder**: **Download data ZIP** gives the same structure as a ZIP.

The folder is a plain mirror of what the Studio knows; the Studio never deletes anything in it.

## 4. Updating

Open the Studio (the add-on), **Mitigation** → **Update from Tenable** (or the **Tenable** button) → **Pull**. The exports load, the register moves (closures dated with the pull date, new findings opened, reopenings counted), the history gets its row, and the data folder receives the pull folder and the refreshed register files. Then build the report as usual; the Excel tracker and the Archive carry the mitigation figures.
