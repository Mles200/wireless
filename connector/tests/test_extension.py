"""The browser add-on: the Studio and Tenable Pull as extension pages can read a Security Center
that sends no CORS headers (the plain mock, like Security Center out of the box), under the
extension's content-security policy (no inline scripts, no eval); the HTML report built inside
the add-on is still a self-contained single file; PDF and Excel generation work under the CSP."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile

import pytest

from trs_connector.synth import dataset_counts

from tests.conftest import ROOT
from tests.test_browser import chrome_path, studio_expectations

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

EXT = ROOT / "dist" / "extension"


@pytest.fixture(scope="module")
def built_extension():
    subprocess.run([sys.executable, str(ROOT / "tools" / "build_extension.py")], check=True, cwd=str(ROOT))
    assert (EXT / "manifest.json").exists()
    return EXT


def launch(p):
    ctx = p.chromium.launch_persistent_context(tempfile.mkdtemp(prefix="trs-ext-"), headless=False, executable_path=chrome_path(),
                                               args=["--headless=new", "--no-sandbox", f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"], viewport={"width": 1360, "height": 900})
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=30000)
    ext_id = sw.url.split("/")[2]
    return ctx, ext_id


def watch(page):
    problems: list[str] = []
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.on("console", lambda m: problems.append(f"console: {m.text}") if m.type == "error" and ("Content Security Policy" in m.text or "Refused to" in m.text) else None)
    return problems


@pytest.mark.skipif(chrome_path() is None, reason="no Chromium for Playwright")
def test_addon_pages_read_a_server_without_cors(built_extension, mock_sc, dataset):
    expect = dataset_counts(dataset)
    manifest = json.loads((EXT / "manifest.json").read_text())
    assert manifest["manifest_version"] == 3 and manifest["host_permissions"] == ["https://*/*", "http://*/*"] and manifest["version"].startswith("4.8")
    with sync_playwright() as p:
        ctx, ext_id = launch(p)
        try:
            # Tenable Pull inside the add-on, against the mock that sends NO CORS headers
            page = ctx.new_page()
            problems = watch(page)
            page.goto(f"chrome-extension://{ext_id}/Tenable_Pull.html")
            assert "add-on" in page.inner_text("#ver")
            page.fill("#tp_url", f"http://127.0.0.1:{mock_sc.port}")
            page.fill("#tp_ak", "AK")
            page.fill("#tp_sk", "SK")
            page.locator(".tp-opts > summary").click()
            page.select_option("#tp_pacing", "fast")
            page.click("#tp_check")
            page.wait_for_selector("#tp_status .notice.good", timeout=30000)
            assert "Tenable Security Center 6.9.0" in page.inner_text("#tp_status")
            page.click("#tp_pull")
            page.wait_for_selector("#tp_result .notice.good", timeout=240000)
            r = page.evaluate("(() => { const r = TP.result(); return r.files.map(f => [f.kind, f.rows, f.hosts]); })()")
            assert r == [["va", expect["va_rows"], expect["va_hosts"]], ["compliance", expect["cmp_rows"], expect["cmp_hosts"]]]
            assert not problems, problems
            # the Studio inside the add-on: the Tenable button pulls from the same server and loads
            studio = ctx.new_page()
            problems2 = watch(studio)
            studio.goto(f"chrome-extension://{ext_id}/ALTANFEETHI_Tenable_Report_Studio.html")
            studio.wait_for_selector("#btnTenable", timeout=30000)
            assert studio.evaluate("document.documentElement.dataset.trsAddon") == manifest["version"]
            studio.click("#btnTenable")
            studio.wait_for_selector("#tenablePanel #tp_pull", timeout=10000)
            studio.fill("#tp_url", f"http://127.0.0.1:{mock_sc.port}")
            studio.fill("#tp_ak", "AK")
            studio.fill("#tp_sk", "SK")
            studio.locator(".tp-opts > summary").click()
            studio.select_option("#tp_pacing", "fast")
            studio.click("#tenablePanel #tp_pull")
            studio.wait_for_selector("#workspace:not([hidden])", timeout=240000)
            studio.wait_for_function("document.querySelectorAll('#fileBar .chip').length === 2", timeout=60000)
            got = studio.evaluate("({findings: state.findings.length, checks: state.checks.length, hosts: state.hosts.size})")
            exp = studio_expectations(dataset)
            assert got == {"findings": exp["findings"], "checks": exp["checks"], "hosts": exp["hosts"]}, got
            # the HTML report is the single-file Studio with the data: inline scripts, no references to the add-on's files
            studio.wait_for_function("SELF_SOURCE.length > 3000000 && !SELF_SOURCE.includes('studio-01.js')", timeout=30000)
            report = studio.evaluate("buildHtmlReport()")
            assert 'id="trs-data"' in report and "STUDIO_VERSION = '4.8'" in report and 'src="studio-' not in report and "extension_glue" not in report
            assert report.count("<script") >= 9, "the vendor libraries and the app are inline in the report"
            # PDF and Excel generation work under the extension CSP (pdfmake and ExcelJS fall back cleanly without eval)
            sizes = studio.evaluate("Promise.all([pdfBlob().then(b => b.size), excelBlob(excelParts()[0]).then(b => b.size)])")
            assert sizes[0] > 50000 and sizes[1] > 20000, sizes
            assert not problems2, problems2
        finally:
            ctx.close()
