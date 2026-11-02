#!/usr/bin/env python3
"""Build the two Tenable Pull deliverables from the sources in studio/src:

  studio/Tenable_Pull.html                      the standalone tool (engine inlined into the template)
  studio/ALTANFEETHI_Tenable_Report_Studio.html the Studio with the engine and the Tenable panel
                                                inlined before </body> (between marker comments,
                                                replaced on every build) and STUDIO_VERSION 4.8

    python3 tools/build_tenable.py            # build both
    python3 tools/build_tenable.py --check    # verify that the built files match the sources
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "studio" / "src"
STUDIO = ROOT / "studio" / "ALTANFEETHI_Tenable_Report_Studio.html"
TOOL = ROOT / "studio" / "Tenable_Pull.html"
START, END = "<!-- trs-tenable:start -->", "<!-- trs-tenable:end -->"
STUDIO_VERSION = "4.8"


def build_tool(engine: str) -> str:
    template = (SRC / "Tenable_Pull.template.html").read_text(encoding="utf-8")
    assert "<!-- @engine -->" in template, "the template has no @engine placeholder"
    return template.replace("<!-- @engine -->", "<script>\n" + engine + "\n</script>")


def build_studio(studio_src: str, engine: str, panel: str) -> str:
    if START in studio_src and END in studio_src:
        a, b = studio_src.index(START), studio_src.index(END) + len(END)
        studio_src = studio_src[:a] + studio_src[b:].lstrip("\n")
    block = f'{START}\n<script id="trs-tenable-engine">\n{engine}\n</script>\n<script id="trs-tenable-panel">\n{panel}\n</script>\n{END}\n'
    at = studio_src.rfind("</body>")
    assert at > 0, "no </body> in the Studio"
    out = studio_src[:at] + block + studio_src[at:]
    out, n = re.subn(r"const STUDIO_VERSION = '[\d.]+';", f"const STUDIO_VERSION = '{STUDIO_VERSION}';", out, count=1)
    assert n == 1, "STUDIO_VERSION not found"
    return out


def main(argv: list[str]) -> int:
    engine = (SRC / "tenable_pull.js").read_text(encoding="utf-8").rstrip()
    panel = (SRC / "studio_panel.js").read_text(encoding="utf-8").rstrip()
    for name, text in (("engine", engine), ("panel", panel)):
        if "</script" in text.lower():
            print(f"ERROR: the {name} source contains a </script> sequence; it cannot be inlined")
            return 1
    tool = build_tool(engine)
    studio = build_studio(STUDIO.read_text(encoding="utf-8"), engine, panel)
    if "--check" in argv:
        ok = TOOL.exists() and TOOL.read_text(encoding="utf-8") == tool and STUDIO.read_text(encoding="utf-8") == studio
        print("built files match the sources" if ok else "built files are out of date: run tools/build_tenable.py")
        return 0 if ok else 1
    TOOL.write_text(tool, encoding="utf-8")
    STUDIO.write_text(studio, encoding="utf-8")
    print(f"wrote {TOOL.relative_to(ROOT)} ({len(tool.encode('utf-8')):,} bytes) and {STUDIO.relative_to(ROOT)} ({len(studio.encode('utf-8')):,} bytes, version {STUDIO_VERSION})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
