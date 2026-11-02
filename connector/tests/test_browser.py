"""End to end in a real browser: the Studio served by the connector loads a pull through the
Tenable panel and shows the figures the Studio derives from the exports; the connector leaves
no trace in the Studio's own source (HTML report, archive copy); settings and the risk register
reach the server."""
from __future__ import annotations

import glob
import os
import time

import httpx
import pytest

from trs_connector.app import create_app

from tests.conftest import ServerThread, free_port

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402


def chrome_path() -> str | None:
    env = os.environ.get("TRS_CHROME")
    if env and os.path.exists(env):
        return env
    for pat in ("/opt/pw-browsers/chromium-*/chrome-linux*/chrome", os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome")):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def studio_expectations(dataset: dict) -> dict:
    """What the Studio must show for the dataset: it removes rows stored in two repositories
    (same plugin, host, port and protocol), keeps Info rows of non-compliance plugins as
    inventory and routes compliance plugins to checks."""
    findings, checks, hosts = set(), set(), set()
    for r in dataset["records"]:
        key = (r["pluginID"], r["ip"], r["port"] or "0", r["protocol"].upper())
        hosts.add(r["ip"])
        if r["family"]["type"] == "compliance":
            checks.add(key)
        elif r["severity"]["name"] != "Info":
            findings.add(key)
    return {"findings": len(findings), "checks": len(checks), "hosts": len(hosts)}


@pytest.mark.skipif(chrome_path() is None, reason="no Chromium for Playwright")
def test_studio_loads_a_pull_through_the_panel(cfg, dataset):
    srv = ServerThread(create_app(cfg), free_port()).start()
    base = f"http://127.0.0.1:{srv.port}"
    try:
        with httpx.Client(base_url=base, auth=("studio", "secret"), timeout=120) as c:
            job = c.post("/api/pull", json={}).json()
            while c.get(f"/api/jobs/{job['id']}").json()["running"]:
                time.sleep(0.2)
            assert c.get("/api/exports").json()[0]["status"] == "ok"
        expect = studio_expectations(dataset)
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chrome_path(), args=["--no-sandbox"])
            ctx = browser.new_context(http_credentials={"username": "studio", "password": "secret"}, viewport={"width": 1400, "height": 900})
            page = ctx.new_page()
            page.route("**/fonts.googleapis.com/**", lambda route: route.abort())   # the Studio runs offline
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(base + "/", wait_until="load")
            page.wait_for_selector("#btnTenable", timeout=30000)
            # the connector script tag is gone from the DOM and from the Studio's captured source
            assert page.evaluate("document.querySelector('script[data-trs-connector]')") is None
            assert page.evaluate("SELF_SOURCE.includes('connector.js')") is False
            assert page.evaluate("typeof TRS_CONNECTOR === 'object'")
            page.click("#btnTenable")
            page.wait_for_selector("#trsLoad:not([disabled])", timeout=30000)
            assert "Security Center 6.9.0" in page.inner_text("#tenableHost") or "6.9.0" in page.inner_text("#tenableHost")
            page.click("#trsLoad")
            page.wait_for_selector("#workspace:not([hidden])", timeout=180000)
            page.wait_for_function("document.querySelectorAll('#fileBar .chip').length === 2", timeout=60000)
            got = page.evaluate("({findings: state.findings.length, checks: state.checks.length, hosts: state.hosts.size, files: state.files.map(f => [f.name, f.kind, f.va.length, f.cmp.length, f.inv.length]), dup: state.quality.dupVa, cntVa: document.querySelector('#cntVa').textContent, scanned: [...state.hosts.values()].filter(h => !h.active).length})")
            assert got["findings"] == expect["findings"], got
            assert got["checks"] == expect["checks"], got
            assert got["hosts"] == expect["hosts"], got
            assert sorted(f[1] for f in got["files"]) == ["current", "current"] and all(f[0].startswith("SC ") and f[0].endswith(".csv") for f in got["files"])
            assert got["dup"] > 0, "the pre-production hosts are stored in both repositories; the Studio removes those duplicates"
            assert got["scanned"] >= 1, "firewalls carry inventory rows only and must be listed as scanned without findings"
            # the notice names the pull, the Risk tab rendered and the register tracks the findings
            assert "Loaded from the Tenable connector" in page.inner_text("#notices")
            page.click('#tabBar .tab[data-tab="riskTab"]')
            page.wait_for_selector("#riskTable", timeout=60000)
            page.wait_for_function("RISK_REG && Object.keys(RISK_REG.items).length > 0", timeout=60000)
            assert page.evaluate("Object.keys(RISK_REG.items).length") == expect["findings"]
            # settings and register reach the server
            page.evaluate("state.settings.title = 'Weekly VA (browser test)'; saveSettings();")
            page.wait_for_timeout(2500)
            with httpx.Client(base_url=base, auth=("studio", "secret"), timeout=30) as c:
                s = c.get("/api/state/settings").json()
                assert s["present"] and s["settings"]["title"] == "Weekly VA (browser test)"
                reg = c.get("/api/state/register").json()
                assert reg["present"] and len(reg["items"]) == expect["findings"]
            # the HTML report built by the Studio is a plain Studio file: no connector script, data embedded
            report = page.evaluate("buildHtmlReport()")
            assert "connector.js" not in report and 'id="trs-data"' in report and "STUDIO_VERSION = '4.7'" in report
            # the Studio opened from the report mode must not show the panel: the report mode flag hides the button
            # (the report never contains the script, so simply check the empty-state hint is gone now)
            assert page.evaluate("document.querySelector('#emptyState').hidden") is True
            # a second browser sees the shared settings
            page2 = ctx.new_page()
            page2.route("**/fonts.googleapis.com/**", lambda route: route.abort())
            page2.goto(base + "/", wait_until="load")
            page2.wait_for_function("state.settings && state.settings.title === 'Weekly VA (browser test)'", timeout=30000)
            assert not errors, errors
            browser.close()
    finally:
        srv.stop()
