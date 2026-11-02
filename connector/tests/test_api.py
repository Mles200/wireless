"""The HTTP service: authentication, the Studio with the injected script, pulls through the API,
exports and downloads, shared state."""
from __future__ import annotations

import base64
import time

import httpx
import pytest

from trs_connector.app import create_app
from trs_connector.synth import dataset_counts

from tests.conftest import ServerThread, free_port


@pytest.fixture()
def service(cfg):
    app = create_app(cfg)
    srv = ServerThread(app, free_port()).start()
    srv.app = app
    yield srv
    srv.stop()


def client(service, auth=("studio", "secret")) -> httpx.Client:
    return httpx.Client(base_url=f"http://127.0.0.1:{service.port}", auth=auth, timeout=60)


def wait_job(c: httpx.Client, job_id: str, timeout=120) -> dict:
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = c.get(f"/api/jobs/{job_id}").json()
        if not j["running"]:
            return j
        time.sleep(0.2)
    raise AssertionError("pull did not finish")


def test_auth_required(service):
    with httpx.Client(base_url=f"http://127.0.0.1:{service.port}", timeout=10) as c:
        assert c.get("/healthz").status_code == 200
        r = c.get("/")
        assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Basic")
        assert c.get("/api/status").status_code == 401
        bad = base64.b64encode(b"studio:nope").decode()
        assert c.get("/api/status", headers={"Authorization": f"Basic {bad}"}).status_code == 401


def test_studio_is_served_with_the_connector_script(service):
    with client(service) as c:
        r = c.get("/")
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
        html = r.text
        assert "Tenable Report Studio" in html and html.count('data-trs-connector="1"') == 1
        tag_at = html.index('<script src="connector.js')
        assert html.rindex("</script>", 0, tag_at) < tag_at < html.rindex("</body>"), "the tag sits after the Studio's own script and before </body>"
        js = c.get("/connector.js")
        assert js.status_code == 200 and "addFiles" in js.text and "javascript" in js.headers["content-type"]
        assert r.headers["cache-control"] == "no-store"
        st = c.get("/api/status").json()
        assert st["studio"]["version"] == "4.7" and st["latest"] is None and st["source"]["type"] == "sc" and st["connector"]["auth"] is True
        assert st["schedule"]["enabled"] is False


def test_pull_through_the_api_and_download(service, dataset):
    expect = dataset_counts(dataset)
    with client(service) as c:
        r = c.post("/api/pull", json={})
        assert r.status_code == 202
        job = r.json()
        assert c.post("/api/pull", json={}).status_code == 409    # one at a time
        done = wait_job(c, job["id"])
        assert done["error"] is None and done["phase"] == "done" and done["pull_id"]
        pulls = c.get("/api/exports").json()
        assert len(pulls) == 1 and pulls[0]["id"] == done["pull_id"] and pulls[0]["status"] == "ok"
        files = {f["kind"]: f for f in pulls[0]["files"]}
        assert files["va"]["rows"] == expect["va_rows"] and files["compliance"]["rows"] == expect["cmp_rows"]
        assert pulls[0]["risk_rules"] == {"accept": 2, "recast": 1} and pulls[0]["scans"] == 4
        # download: gzip on disk, decoded transparently for the browser, with the display name
        r = c.get(f"/api/exports/{done['pull_id']}/files/{files['va']['name']}")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
        assert r.headers["x-export-file"].endswith(".csv") and not r.headers["x-export-file"].endswith(".gz")
        text = r.text
        assert text.startswith("﻿Plugin,Plugin Name") and text.count("\r\n") == expect["va_rows"] + 1
        assert c.get(f"/api/exports/{done['pull_id']}/files/{files['va']['name']}?download=1").headers["content-disposition"].startswith("attachment")
        m = c.get(f"/api/exports/{done['pull_id']}").json()
        assert m["status"] == "ok" and m["queries"][0]["name"] == "vulnerabilities"
        rules = c.get(f"/api/exports/{done['pull_id']}/risk-rules").json()
        assert len(rules["accept"]) == 2 and rules["recast"][0]["newSeverity"]["name"] == "Medium"
        scans = c.get(f"/api/exports/{done['pull_id']}/scans").json()
        assert len(scans["results"]) == 4
        st = c.get("/api/status").json()
        assert st["latest"]["id"] == done["pull_id"] and st["job"]["running"] is False and st["store"]["pulls"] == 1
        # traversal and unknown names
        assert c.get(f"/api/exports/{done['pull_id']}/files/..%2Fmanifest.json").status_code in (404, 400)
        assert c.get("/api/exports/nope").status_code == 404
        # live reads against the mock
        chk = c.get("/api/tenable/check").json()
        assert chk["ok"] and chk["version"] == "6.9.0" and len(chk["repositories"]) == 2
        assert len(c.get("/api/tenable/scans").json()["results"]) == 4
        # delete
        assert c.delete(f"/api/exports/{done['pull_id']}").status_code == 200
        assert c.get("/api/exports").json() == []


def test_shared_state(service):
    with client(service) as c:
        assert c.get("/api/state/settings").json() == {"present": False}
        r = c.put("/api/state/settings", json={"trsSettings": 1, "settings": {"title": "Weekly"}, "updated": 1})
        assert r.status_code == 200
        got = c.get("/api/state/settings").json()
        assert got["present"] and got["settings"]["title"] == "Weekly" and got["server_updated"]
        # the register with optimistic concurrency
        r = c.put("/api/state/register", json={"trsRisk": 1, "items": {"1|10.0.0.1": {"status": "Open"}}, "overrides": {}, "exportDate": 5})
        base = r.json()["server_updated"]
        r2 = c.put("/api/state/register", json={"trsRisk": 1, "items": {}, "overrides": {}, "if_server_updated": base - 100})
        assert r2.status_code == 409
        r3 = c.put("/api/state/register", json={"trsRisk": 1, "items": {"a": 1}, "overrides": {}, "if_server_updated": base})
        assert r3.status_code == 200 and c.get("/api/state/register").json()["items"] == {"a": 1}
        assert c.get("/api/state/other").status_code == 404
        assert c.put("/api/state/settings", content=b"[]", headers={"Content-Type": "application/json"}).status_code == 400


def test_shared_state_can_be_disabled(cfg):
    cfg.studio.shared_state = False
    srv = ServerThread(create_app(cfg), free_port()).start()
    try:
        with client(srv) as c:
            assert c.get("/api/state/settings").status_code == 404
    finally:
        srv.stop()


def test_config_is_masked(service):
    with client(service) as c:
        text = c.get("/api/config").text
        assert '"access_key": "***"' in text and '"secret_key": "***"' in text
        assert '"AK"' not in text and '"SK"' not in text and '"secret"' not in text and '"password": "***"' in text
