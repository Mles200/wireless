"""The Mitigation tab and the data folder: two pulls two weeks apart through the Studio's Tenable
button (the mock serves a later scan for the second pull: two products patched everywhere, one
host not scanned, one new finding), the figures the register derives, the per-pull history, the
Excel tracker, and the data folder written and read back (the browser's private file system
stands in for the Desktop folder, same API)."""
from __future__ import annotations

import copy

import pytest

from trs_connector.mock_sc import create_mock_app
from trs_connector.synth import evolve_dataset

from tests.conftest import STUDIO, ServerThread, free_port
from tests.test_browser import chrome_path

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

DROP_PLUGINS = (209293, 206896)      # Microsoft Edge, VMware Tools: patched everywhere in the second scan


def pairs(dataset: dict) -> set[tuple[str, str]]:
    """The register's keys for a dataset: one per plugin per host among the vulnerability findings (Info rows and compliance excluded)."""
    return {(r["pluginID"], r["ip"]) for r in dataset["records"] if r["family"]["type"] != "compliance" and r["severity"]["name"] != "Info"}


def second_scan(dataset: dict) -> tuple[dict, dict]:
    dropped_host = next(h["ip"] for h in dataset["hosts"] if h["env"] == "prod")
    other_host = next(h["ip"] for h in dataset["hosts"] if h["env"] == "prod" and h["ip"] != dropped_host)
    template = next(r for r in dataset["records"] if r["ip"] == other_host and r["family"]["type"] != "compliance" and r["severity"]["name"] != "Info")
    new = copy.deepcopy(template)
    shift = 14 * 86400
    new.update({"pluginID": "999999", "pluginName": "Synthetic new finding (second scan)", "severity": {"id": "3", "name": "High"}, "port": "0", "protocol": "tcp",
                "firstSeen": str(dataset["scan_ts"] + shift - 2 * 86400), "lastSeen": str(dataset["scan_ts"] + shift - 3600), "pluginText": "new"})
    b = evolve_dataset(dataset, days=14, drop_plugins=DROP_PLUGINS, drop_hosts=(dropped_host,), add=[new])
    a_pairs = pairs(dataset)
    expect = {
        "mitigated": len([p for p in a_pairs if int(p[0]) in DROP_PLUGINS and p[1] != dropped_host]),
        "unverified": len([p for p in a_pairs if p[1] == dropped_host]),
        "new": 1,
        "hosts_after": len(b["hosts"]),
        "open_before": len(a_pairs),
    }
    expect["open_after"] = expect["open_before"] - expect["mitigated"] - expect["unverified"] + expect["new"]
    expect["dropped_host"] = dropped_host
    # the remediation actions of the two patched products: VMware Tools has one plugin (206896); Microsoft Edge has two (209293 patched, 208754 still open)
    count = lambda plugin, on_dropped: len([p for p in a_pairs if p[0] == str(plugin) and ((p[1] == dropped_host) == on_dropped)])   # noqa: E731
    expect["vmware"] = {"closed": count(206896, False), "unverified": count(206896, True), "open": 0}
    expect["vmware"]["state"] = "Done" if expect["vmware"]["unverified"] == 0 else "In progress"
    expect["edge"] = {"closed": count(209293, False), "unverified": count(209293, True) + count(208754, True), "open": count(208754, False)}
    expect["edge"]["state"] = "Done" if expect["edge"]["open"] + expect["edge"]["unverified"] == 0 else ("In progress" if expect["edge"]["closed"] else "Not started")
    return b, expect


def pull(page, port):
    page.click("#btnTenable")
    page.wait_for_selector("#tenablePanel #tp_pull", timeout=10000)
    page.fill("#tp_url", f"http://127.0.0.1:{port}")
    page.fill("#tp_ak", "AK")
    page.fill("#tp_sk", "SK")
    page.locator(".tp-opts > summary").click()
    page.select_option("#tp_pacing", "fast")
    page.click("#tenablePanel #tp_pull")
    page.wait_for_function("document.querySelector('#modalHost').hidden === true", timeout=240000)
    page.wait_for_function("RISK_REG && RISK_REG.history && RISK_REG.history.length > 0", timeout=60000)


MIT = """(() => { const D = TRS_MITIGATION.data('prev'); return { open: D.open.length, mitigated: D.mitigated.length, unverified: D.unverified.length, newOpen: D.newOpen.length, reopened: D.reopened.length,
  absentHosts: D.absentHosts.length, hosts: [...state.hosts.values()].length, history: D.history.map(e => [fmtDate(e.date), e.open.total, e.closed, e.opened, e.unverified, e.hosts, e.hostsAbsent]),
  actions: D.byAction.length, done: D.byAction.filter(a => a.state === 'Done').length, cnt: document.querySelector('#cntMit').textContent, stale: D.stale }; })()"""


@pytest.mark.skipif(chrome_path() is None, reason="no Chromium for Playwright")
def test_two_pulls_show_mitigated_pending_and_environment(dataset):
    b, expect = second_scan(dataset)
    app = create_mock_app(dataset, "AK", "SK", allow_cors=True)

    @app.get("/healthz")
    async def hz():
        return {"ok": True}
    # the Studio is served from the same origin as the mock (like the add-on's own origin): the browser's private file
    # system, which stands in for the Desktop folder below, is not available to a page opened from a file
    from fastapi.staticfiles import StaticFiles
    app.mount("/studio", StaticFiles(directory=str(STUDIO.parent)), name="studio")
    srv = ServerThread(app, free_port()).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chrome_path(), args=["--no-sandbox"])
            ctx = browser.new_context(viewport={"width": 1400, "height": 900})
            ctx.route("**/fonts.googleapis.com/**", lambda route: route.abort())
            page = ctx.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{srv.port}/studio/{STUDIO.name}")
            page.wait_for_selector("#btnTenable", timeout=30000)
            assert page.locator('#tabBar .tab[data-tab="mitTab"]').count() == 1
            # first pull: everything open, one history entry, nothing mitigated
            pull(page, srv.port)
            page.wait_for_function("document.querySelector('#cntMit').textContent !== '0'", timeout=30000)
            m1 = page.evaluate(MIT)
            assert m1["open"] == expect["open_before"] and m1["mitigated"] == 0 and m1["unverified"] == 0 and m1["newOpen"] == 0, m1
            assert len(m1["history"]) == 1 and m1["history"][0][0] == "2026-10-25" and m1["history"][0][1] == expect["open_before"], m1
            assert m1["cnt"] == f"{expect['open_before']:,}"
            # the second scan, two weeks later
            app.state.data = b
            pull(page, srv.port)
            page.wait_for_function("RISK_REG.history.length === 2", timeout=60000)
            m2 = page.evaluate(MIT)
            assert m2["mitigated"] == expect["mitigated"] > 0, m2
            assert m2["unverified"] == expect["unverified"] > 0 and m2["absentHosts"] == 1, m2
            assert m2["newOpen"] == expect["new"] and m2["reopened"] == 0, m2
            assert m2["open"] == expect["open_after"], m2
            assert m2["hosts"] == expect["hosts_after"] and m2["history"][1][0] == "2026-11-08", m2
            assert m2["history"][1] == ["2026-11-08", expect["open_after"], expect["mitigated"], expect["new"], expect["unverified"], expect["hosts_after"], 1], m2
            assert not m2["stale"]
            # progress per remediation action: the patched products
            act = page.evaluate("""(() => { const D = TRS_MITIGATION.data('prev'); const pick = p => { const a = D.byAction.find(x => x.plugins.has(p)); return a && { state: a.state, open: a.open, closed: a.closed, mitigated: a.mitigated, unverified: a.unverified, action: a.action }; }; return { vmware: pick(206896), edge: pick(209293) }; })()""")
            for key in ("vmware", "edge"):
                got, exp = act[key], expect[key]
                assert got and got["state"] == exp["state"] and got["open"] == exp["open"] and got["closed"] == exp["closed"] and got["unverified"] == exp["unverified"] and got["mitigated"] == exp["closed"], (key, got, exp)
            assert "VMware Tools" in act["vmware"]["action"] and "Microsoft Edge" in act["edge"]["action"]
            # the tab renders: tables, the remediation action of the patched product is Done, the absent host is listed
            page.click('#tabBar .tab[data-tab="mitTab"]')
            page.wait_for_selector("#mitTab .kpis", timeout=10000)
            text = page.inner_text("#mitTab")
            assert "Microsoft Edge" in text and "VMware Tools" in text and expect["dropped_host"] in text and ("Done" in text or "In progress" in text)
            assert "Pull date" not in text   # the history is drawn as charts here, the table is in the Excel
            # the Excel tracker builds
            size = page.evaluate("TRS_MITIGATION.excel().then(b => b.size)")
            assert size > 20000
            # the data folder: the private file system stands in for a Desktop folder (same handle API)
            page.evaluate("navigator.storage.getDirectory().then(root => TRS_MITIGATION.useFolder(root))")
            page.wait_for_function("TRS_MITIGATION.pulls().length === 2", timeout=30000)
            listing = page.evaluate("""(async () => { const root = await navigator.storage.getDirectory(); const out = {};
              for await (const [name, h] of root.entries()) out[name] = h.kind;
              const pulls = await root.getDirectoryHandle('pulls'); out.pulls = []; for await (const [name, h] of pulls.entries()) { const files = []; for await (const [fn] of h.entries()) files.push(fn); out.pulls.push([name, files.sort()]); }
              const reg = await root.getDirectoryHandle('register'); const csv = await (await (await reg.getFileHandle('findings-register.csv')).getFile()).text(); const hist = JSON.parse(await (await (await reg.getFileHandle('history.json')).getFile()).text());
              const readme = await (await (await root.getFileHandle('README.txt')).getFile()).text();
              out.csvHead = csv.split('\\r\\n')[0]; out.csvRows = csv.trim().split('\\r\\n').length - 1; out.hist = hist.length; out.readme = readme.slice(0, 40); return out; })()""")
            assert listing["pulls"] and listing["register"] == "directory" and listing["reports"] == "directory"
            names = dict(listing["pulls"])
            assert set(names) == {"2026-10-25", "2026-11-08"}, names
            assert any(f.startswith("SC VA export") for f in names["2026-11-08"]) and "manifest.json" in names["2026-11-08"] and "risk-rules.json" in names["2026-11-08"]
            assert listing["csvHead"].lstrip("﻿").startswith("Status,Severity,Plugin ID") and listing["csvRows"] == expect["open_before"] + expect["new"]   # File.text() drops the BOM
            assert listing["hist"] == 2 and "Tenable data folder" in listing["readme"]
            # the Studio reads a pull back from the folder: remove the loaded files (empty state), open the data folder from there, Load the older pull
            page.evaluate("state.files = []; classifyFiles(); rebuild();")
            page.wait_for_function("document.querySelector('#emptyState').hidden === false", timeout=10000)
            page.wait_for_function("document.querySelector('#mitEmptyHint') && document.querySelector('#mitEmptyHint').innerText.includes('2 pulls stored')", timeout=10000)
            page.click("#btnDataFolder")
            page.wait_for_selector("#modalHost [data-mitload]", timeout=10000)
            assert page.locator("#modalHost [data-mitload]").count() == 2
            page.locator("#modalHost [data-mitload]").last.click()   # newest first, so the last is the older pull
            page.wait_for_selector("#workspace:not([hidden])", timeout=120000)
            page.wait_for_function("document.querySelector('#modalHost').hidden === true", timeout=10000)
            loaded = page.evaluate("state.files.map(f => [f.name, f.kind])")
            assert all(n.endswith("2026-10-25.csv") for n, _ in loaded) and all(k == "current" for _, k in loaded), loaded
            # the register is stale against an older pull: nothing moved, the notice says so
            page.wait_for_function("RISK_REG.stale != null && RISK_REG.stale > 0", timeout=10000)
            assert "older than the pull the register last saw" in page.inner_text("#mitTab")
            assert not errors, errors
            browser.close()
    finally:
        srv.stop()
