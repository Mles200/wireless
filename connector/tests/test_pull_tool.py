"""The lightweight tool, end to end in Chromium: Tenable_Pull.html opened from a folder (file://)
against a Security Center that allows the page to read its API (CORS headers, as after the
Apache change or when the file is served from the Security Center itself), with every 7th
analysis request refused with HTTP 429; then the hand-over to the Studio, the Studio's own
Tenable button, and the precise message when a server does not allow the page (plain mock)."""
from __future__ import annotations

import pytest

from trs_connector.mock_sc import create_mock_app
from trs_connector.synth import dataset_counts

from tests.conftest import ROOT, STUDIO, ServerThread, free_port
from tests.test_browser import chrome_path, studio_expectations

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

TOOL = ROOT / "studio" / "Tenable_Pull.html"


@pytest.fixture(scope="module")
def cors_sc(dataset):
    app = create_mock_app(dataset, "AK", "SK", allow_cors=True, rate_limit_every=7)

    @app.get("/healthz")
    async def hz():
        return {"ok": True}
    srv = ServerThread(app, free_port()).start()
    srv.app = app
    yield srv
    srv.stop()


def browser(p):
    b = p.chromium.launch(executable_path=chrome_path(), args=["--no-sandbox"])
    ctx = b.new_context(viewport={"width": 1360, "height": 900})
    ctx.route("**/fonts.googleapis.com/**", lambda route: route.abort())
    return b, ctx


def connect(page, port, pacing="fast"):
    page.fill("#tp_url", f"http://127.0.0.1:{port}")
    page.fill("#tp_ak", "AK")
    page.fill("#tp_sk", "SK")
    page.locator(".tp-opts > summary").click()
    page.select_option("#tp_pacing", pacing)
    page.fill("#tp_page", "100")      # small pages: enough requests to meet the 429s
    page.fill("#tp_cpage", "100")


@pytest.mark.skipif(chrome_path() is None, reason="no Chromium for Playwright")
def test_tool_pulls_from_a_folder_and_hands_over_to_the_studio(cors_sc, dataset):
    assert TOOL.exists(), "run tools/build_tenable.py"
    expect = dataset_counts(dataset)
    with sync_playwright() as p:
        b, ctx = browser(p)
        page = ctx.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(TOOL.as_uri())
        assert page.title() == "Tenable Pull" and "version 1.0" in page.inner_text("#ver")
        connect(page, cors_sc.port)
        page.click("#tp_check")
        page.wait_for_selector("#tp_status .notice.good", timeout=30000)
        status = page.inner_text("#tp_status")
        assert "Security Center 6.9.0" in status and "studio.api" in status and "Vulnerability Repository" in status
        assert page.locator("#tp_repos input").count() == 2
        page.click("#tp_pull")
        page.wait_for_selector("#tp_result .notice.good", timeout=240000)
        r = page.evaluate("""(() => { const r = TP.result(); return { files: r.files.map(f => ({ name: f.name, kind: f.kind, rows: f.rows, hosts: f.hosts, severity: f.severity })),
            dup: r.counts.duplicatesSkipped, rules: [r.rules.accept.length, r.rules.recast.length], scans: r.scans.length, transport: r.transportStats, warnings: r.warnings, first: r.files[0].csv.text().slice(0, 60), lines: r.files[0].csv.text().split('\\r\\n').length - 1 }; })()""")
        files = {f["kind"]: f for f in r["files"]}
        assert files["va"]["rows"] == expect["va_rows"] and files["va"]["hosts"] == expect["va_hosts"] and files["va"]["severity"] == expect["severity"], r
        assert files["compliance"]["rows"] == expect["cmp_rows"] and files["compliance"]["hosts"] == expect["cmp_hosts"]
        assert files["va"]["name"].startswith("SC VA export ") and files["compliance"]["name"].startswith("SC Compliance export ")
        assert r["rules"] == [2, 1] and r["scans"] == 4 and r["warnings"] == []
        assert r["first"].startswith("﻿Plugin,Plugin Name,Family,Severity,IP Address") and r["lines"] == expect["va_rows"] + 1
        assert r["transport"]["retries"] >= 1 and cors_sc.app.state.rate_limited >= 1, "the 429s must have been retried"
        assert r["transport"]["requests"] > 8 and "requests, one at a time" in page.inner_text("#tp_result")
        # the keys: access key remembered, the secret not (Remember unticked)
        stored = page.evaluate("JSON.parse(localStorage.getItem('trs.tenable'))")
        assert stored["accessKey"] == "AK" and "secretKey" not in stored and stored["pacing"] == "fast"
        # risk acceptances rendered
        page.locator("#tp_result details.tp-sect").first.locator("summary").click()
        assert "SMB signing exception" in page.inner_text("#tp_result")
        # hand-over to the Studio (a popup opened from the file, the Studio answers trs-ready, the files arrive)
        page.fill("#tp_studio", STUDIO.as_uri())
        with page.expect_popup() as popup:
            page.click("#tp_send")
        studio = popup.value
        studio.wait_for_selector("#workspace:not([hidden])", timeout=240000)
        studio.wait_for_function("document.querySelectorAll('#fileBar .chip').length === 2", timeout=60000)
        got = studio.evaluate("({findings: state.findings.length, checks: state.checks.length, hosts: state.hosts.size, version: STUDIO_VERSION, files: state.files.map(f => f.name)})")
        exp = studio_expectations(dataset)
        assert got["findings"] == exp["findings"] and got["checks"] == exp["checks"] and got["hosts"] == exp["hosts"], got
        assert got["version"] == "4.8" and all(n.startswith("SC ") for n in got["files"])
        assert "sent by Tenable Pull" in studio.inner_text("#notices")
        assert "sent to the Studio" in page.inner_text("#tp_send_status")
        assert not errors, errors
        b.close()


@pytest.mark.skipif(chrome_path() is None, reason="no Chromium for Playwright")
def test_studio_tenable_button_pulls_directly(cors_sc, dataset):
    with sync_playwright() as p:
        b, ctx = browser(p)
        page = ctx.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(STUDIO.as_uri())
        page.wait_for_selector("#btnTenable", timeout=30000)
        assert page.evaluate("document.querySelector('#btnConnector')") is None, "the connector panel is only there when the connector serves the page"
        page.click("#btnTenable")
        page.wait_for_selector("#tenablePanel #tp_pull", timeout=10000)
        connect(page, cors_sc.port)
        page.click("#tenablePanel #tp_pull")
        page.wait_for_selector("#workspace:not([hidden])", timeout=240000)
        page.wait_for_function("document.querySelectorAll('#fileBar .chip').length === 2", timeout=60000)
        got = page.evaluate("({findings: state.findings.length, checks: state.checks.length, hosts: state.hosts.size, modal: document.querySelector('#modalHost').hidden})")
        exp = studio_expectations(dataset)
        assert got["findings"] == exp["findings"] and got["checks"] == exp["checks"] and got["hosts"] == exp["hosts"] and got["modal"] is True, got
        assert "Loaded from Tenable Security Center 6.9.0" in page.inner_text("#notices")
        # the HTML report keeps the panel code but it is inert there, and the archive copy keeps it too
        report = page.evaluate("buildHtmlReport()")
        assert "trs-tenable-panel" in report and 'id="trs-data"' in report
        assert not errors, errors
        b.close()


@pytest.mark.skipif(chrome_path() is None, reason="no Chromium for Playwright")
def test_blocked_server_is_explained(mock_sc):
    """The plain mock sends no CORS headers, like Security Center out of the box."""
    with sync_playwright() as p:
        b, ctx = browser(p)
        page = ctx.new_page()
        page.goto(TOOL.as_uri())
        connect(page, mock_sc.port)
        page.click("#tp_check")
        page.wait_for_selector("#tp_status .notice.bad", timeout=30000)
        page.wait_for_function("document.querySelector('#tp_progress').innerText.includes('Diagnosis')", timeout=30000)
        text = page.inner_text("#tp_status") + page.inner_text("#tp_progress")
        assert "could not get an answer" in text and "Access-Control-Allow-Origin" in text and "If the connection is blocked" in text
        assert "disable-web-security" in text and "/opt/sc/support/conf" in text
        # the no-cors probe tells that the server is there and only blocks the page
        assert "Diagnosis: the server is there" in text and "does not allow this page" in text
        # and a host with nothing listening is diagnosed as no connection, with the usual ports probed
        d = page.evaluate("TenablePull.diagnoseConnection('https://127.0.0.1:1', 'sc')")
        assert d["reachable"] is False and len(d["alternatives"]) == 5 and all(a["reachable"] is False for a in d["alternatives"])
        html = page.evaluate("TenablePull.diagnosisHtml(%s)" % __import__("json").dumps(d))
        assert "no connection at all" in html and "None of the usual ports" in html
        d2 = page.evaluate("TenablePull.diagnoseConnection('https://127.0.0.1:1', 'sc').then(x => { x.alternatives[1].reachable = true; return TenablePull.diagnosisHtml(x); })")
        assert "Something answers at" in d2 and "127.0.0.1:8000" in d2
        b.close()
