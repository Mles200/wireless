#!/usr/bin/env python3
"""Apply the v4.7 changes to the Studio HTML (exact-string patches, each verified).

    python3 tools/patch_studio.py studio/ALTANFEETHI_Tenable_Report_Studio.html          # apply
    python3 tools/patch_studio.py studio/ALTANFEETHI_Tenable_Report_Studio.html --check  # verify only

Every patch is an exact text replacement with a unique anchor.  A patch that is already applied
is skipped; an anchor that is missing and whose replacement is not present either stops the
run, so the script never half-patches a file.
"""
from __future__ import annotations

import sys
from pathlib import Path

PATCHES = [
    ("version 4.7",
     "const STUDIO_VERSION = '4.6';",
     "const STUDIO_VERSION = '4.7';"),
    ("escape file names and error text in the load notice (a file named like <img src=x onerror=…>.csv ran script in the Studio)",
     "if (errors.length) showNotice(errors.join('<br>'), 'bad');",
     "if (errors.length) showNotice(errors.map(esc).join('<br>'), 'bad');"),
    ("escape the CVE list under a vulnerability name (Vulnerabilities tab)",
     "${c.cve.size ? ' · ' + [...c.cve].slice(0,3).join(', ') + (c.cve.size>3 ? ` +${c.cve.size-3}` : '') : ''}",
     "${c.cve.size ? ' · ' + esc([...c.cve].slice(0,3).join(', ')) + (c.cve.size>3 ? ` +${c.cve.size-3}` : '') : ''}"),
    ("escape the CVE list under a vulnerability name (Risk tab)",
     "${g.cve.size ? [...g.cve].slice(0, 3).join(', ') + (g.cve.size > 3 ? ` +${g.cve.size - 3}` : '') : ''}",
     "${g.cve.size ? esc([...g.cve].slice(0, 3).join(', ')) + (g.cve.size > 3 ? ` +${g.cve.size - 3}` : '') : ''}"),
    ("escape the 'See also' text of a CIS check (Compliance tab) consistently with the other tabs",
     "${c.seeAlso ? `<b>See also</b><div class=\"small\">${linkify(c.seeAlso)}</div>` : ''}</div>\n      <details style=\"margin-top:8px\"><summary class=\"link\">Actual value per host",
     "${c.seeAlso ? `<b>See also</b><div class=\"small\">${linkify(c.seeAlso).replace(/\\n/g,'<br>')}</div>` : ''}</div>\n      <details style=\"margin-top:8px\"><summary class=\"link\">Actual value per host"),
]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = Path(argv[1])
    check = "--check" in argv
    src = path.read_text(encoding="utf-8")
    out = src
    applied = skipped = 0
    for title, old, new in PATCHES:
        if title.startswith("version"):   # the version line is owned by tools/build_tenable.py once the Tenable panel is built in
            import re
            m = re.search(r"const STUDIO_VERSION = '(\d+)\.(\d+)';", out)
            if m and (int(m.group(1)), int(m.group(2))) >= (4, 7):
                skipped += 1
                print(f"present: {title} (file is {m.group(1)}.{m.group(2)})")
                continue
        if old in out:
            if out.count(old) != 1:
                print(f"ERROR: anchor is not unique for: {title}")
                return 1
            if check:
                print(f"missing: {title}")
                continue
            out = out.replace(old, new)
            applied += 1
            print(f"applied: {title}")
        elif new in out:
            skipped += 1
            print(f"present: {title}")
        else:
            print(f"ERROR: neither the anchor nor the replacement was found for: {title}")
            return 1
    if check:
        missing = len(PATCHES) - skipped
        print(f"{skipped} of {len(PATCHES)} patches present")
        return 0 if missing == 0 else 1
    if applied:
        path.write_text(out, encoding="utf-8")
    print(f"{applied} applied, {skipped} already present -> {path} ({len(out):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
