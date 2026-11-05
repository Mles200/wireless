#!/usr/bin/env python3
"""Build the browser add-on (Chrome / Edge, Manifest V3) that carries the Studio and Tenable Pull.

    python3 tools/build_extension.py                       # -> dist/extension/ and dist/Tenable_Report_Studio_addon.zip
    python3 tools/build_extension.py --hosts https://10.70.30.3 https://10.70.30.3:8834
                                                           # narrow host_permissions to those origins (default: any https / http host)

Why an add-on: a page opened from a folder may not read the answers of another server unless that
server allows it (CORS), and Security Center does not.  Extension pages may call the hosts listed
under host_permissions without that restriction, so nothing changes on the Security Center server
and browser security stays on.

What the build does: the extension CSP forbids inline scripts, so every inline <script> of the
built Studio becomes a file (studio-NN.js) referenced from the page; the single-file Studio is
shipped alongside (studio.single.html) and put back into SELF_SOURCE at start-up so the HTML
report and the archive copy remain self-contained files.  Tenable_Pull.html gets the engine as a
file and its start-up script from extension-src.
"""
from __future__ import annotations

import json
import re
import shutil
import struct
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "studio" / "src"
EXT_SRC = ROOT / "studio" / "extension-src"
STUDIO = ROOT / "studio" / "ALTANFEETHI_Tenable_Report_Studio.html"
OUT = ROOT / "dist" / "extension"
ZIP = ROOT / "dist" / "Tenable_Report_Studio_addon.zip"
VERSION_RE = re.compile(r"const STUDIO_VERSION = '([\d.]+)';")


def png(size: int, rgb: tuple[int, int, int]) -> bytes:
    """A solid PNG (the add-on icon), pure Python."""
    raw = b"".join(b"\x00" + bytes(rgb) * size for _ in range(size))
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def externalise_scripts(html: str, prefix: str, out_dir: Path) -> tuple[str, list[str]]:
    """Every inline <script>…</script> becomes a file; the tag gets a src.  Scripts that already have a src are kept."""
    files: list[str] = []
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        attrs, body = m.group(1), m.group(2)
        if re.search(r"\bsrc\s*=", attrs) or re.search(r'type\s*=\s*"application/json"', attrs):
            return m.group(0)
        n += 1
        name = f"{prefix}-{n:02d}.js"
        (out_dir / name).write_text(body, encoding="utf-8")
        files.append(name)
        return f'<script src="{name}"{attrs}></script>'
    return re.sub(r"<script([^>]*)>(.*?)</script>", repl, html, flags=re.S), files


def main(argv: list[str]) -> int:
    hosts = ["https://*/*", "http://*/*"]
    if "--hosts" in argv:
        given = argv[argv.index("--hosts") + 1:]
        hosts = []
        for h in given:
            h = h.rstrip("/")
            if not re.match(r"^https?://", h):
                h = "https://" + h
            hosts.append(h + "/*")
        if not hosts:
            print("ERROR: --hosts needs at least one origin")
            return 1
    studio_src = STUDIO.read_text(encoding="utf-8")
    m = VERSION_RE.search(studio_src)
    version = (m.group(1) if m else "0.0") + ".0"
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "icons").mkdir(parents=True)
    # the Studio: scripts out, glue in, single-file copy alongside
    html, files = externalise_scripts(studio_src, "studio", OUT)
    html = html.replace("</body>", '<script src="extension_glue.js"></script>\n</body>', 1)
    (OUT / "ALTANFEETHI_Tenable_Report_Studio.html").write_text(html, encoding="utf-8")
    (OUT / "studio.single.html").write_text(studio_src, encoding="utf-8")
    shutil.copyfile(EXT_SRC / "extension_glue.js", OUT / "extension_glue.js")
    # Tenable Pull: the template with the engine and the start-up script as files
    template = (SRC / "Tenable_Pull.template.html").read_text(encoding="utf-8")
    tool = template.replace("<!-- @engine -->", '<script src="tenable_pull.js"></script>')
    tool = re.sub(r"<script>\s*\(function\(\)\{.*?\}\)\(\);\s*</script>", '<script src="tenable_pull_page.js"></script>', tool, count=1, flags=re.S)
    assert 'src="tenable_pull_page.js"' in tool, "the template's start-up script was not found"
    (OUT / "Tenable_Pull.html").write_text(tool, encoding="utf-8")
    shutil.copyfile(SRC / "tenable_pull.js", OUT / "tenable_pull.js")
    shutil.copyfile(EXT_SRC / "tenable_pull_page.js", OUT / "tenable_pull_page.js")
    # popup, background, manifest, icons
    for name in ("popup.html", "popup.js", "background.js"):
        shutil.copyfile(EXT_SRC / name, OUT / name)
    manifest = (EXT_SRC / "manifest.template.json").read_text(encoding="utf-8").replace("__VERSION__", version).replace("__HOSTS__", json.dumps(hosts))
    json.loads(manifest)
    (OUT / "manifest.json").write_text(manifest, encoding="utf-8")
    for size in (16, 48, 128):
        (OUT / "icons" / f"{size}.png").write_bytes(png(size, (168, 104, 59)))
    # the zip the user installs from (unzip, then "Load unpacked")
    ZIP.parent.mkdir(exist_ok=True)
    install = f"""Tenable Report Studio add-on {version} (ALTANFEETHI Cybersecurity)
=====================================================================

The Tenable Report Studio and Tenable Pull packaged as a Chrome / Edge extension, so that they
can read the Security Center API from the browser (a page opened from a folder is blocked by
CORS; an extension page is not). Nothing changes on the Security Center server.

Install (once):
  1. Unzip into a permanent folder, for example C:\\Tenable\\Tenable_Report_Studio_addon
     (the browser loads the add-on from that folder every time; do not delete or move it).
  2. Edge: open edge://extensions, switch on "Developer mode" (left pane), click "Load unpacked",
     choose the folder Tenable_Report_Studio_addon.
     Chrome: chrome://extensions, "Developer mode" (top right), "Load unpacked".
  3. The Studio opens by itself. Later: click the copper icon in the toolbar (pin it) and choose
     "Open the Tenable Report Studio".

Use:
  Studio > Tenable > endpoint (the address you log in to the Security Center console with, for
  example https://10.70.30.3), the service account's access key and secret key > Check connection
  > Pull. The exports load into the Studio; build the report as usual.

Notes:
  - Settings and the risk register of the add-on's Studio are separate from a Studio opened from a
    folder: export settings.json and risk-register.json from the old one and drop them on this one.
  - The HTML report and the archive copy produced here are ordinary single-file Studios.
  - Permissions: the add-on may call any https/http host because the endpoint is typed in; it only
    calls the one you enter. tools/build_extension.py --hosts https://10.70.30.3 builds a copy
    limited to that server.
  - Update: unzip the new version over the folder, then click the reload arrow on edge://extensions.
  - If "Load unpacked" is greyed out, a browser policy blocks developer-mode extensions: ask IT to
    allow it, or to distribute the add-on through the ExtensionInstallForcelist policy.
"""
    (OUT / "INSTALL.txt").write_text(install, encoding="utf-8")
    with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("INSTALL.txt", install)
        for p in sorted(OUT.rglob("*")):
            if p.is_file():
                z.write(p, f"Tenable_Report_Studio_addon/{p.relative_to(OUT)}")
    total = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
    print(f"built {OUT.relative_to(ROOT)} (version {version}, {len(files)} Studio scripts, host_permissions {hosts}, {total / 1048576:.1f} MB) and {ZIP.relative_to(ROOT)} ({ZIP.stat().st_size / 1048576:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
