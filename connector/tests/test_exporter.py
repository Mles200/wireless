"""The pull against the mock Security Center: files, counts, column fidelity with the Studio."""
from __future__ import annotations

import csv
import gzip
import json
import re
from pathlib import Path

import pytest

from trs_connector.export_schema import HEADERS, STUDIO_COLS, STUDIO_KEYS, fmt_date, sc_record_to_row
from trs_connector.exporter import PullProgress, pull_security_center
from trs_connector.sc_client import SCError, SecurityCenterClient
from trs_connector.store import ExportStore, read_export
from trs_connector.synth import dataset_counts

ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def test_every_studio_column_has_an_export_header():
    """Each key the Studio reads (COLS in the Studio) must be satisfied by one of our headers,
    except OS which is not an export column."""
    for key, aliases in STUDIO_COLS.items():
        if key == "os":
            continue
        assert any(a in HEADERS for a in aliases), f"Studio key {key!r} has no header among {aliases}"
    assert set(STUDIO_KEYS.values()) <= set(STUDIO_COLS), "unknown Studio key in the schema"


def test_fmt_date():
    from datetime import datetime, timezone
    ts = int(datetime(2026, 10, 25, 6, 0, 0, tzinfo=timezone.utc).timestamp())
    assert fmt_date(str(ts)) == "2026-10-25T06:00:00Z"
    assert fmt_date(ts) == "2026-10-25T06:00:00Z"
    assert fmt_date(ts * 1000) == "2026-10-25T06:00:00Z"
    assert fmt_date("-1") == "" and fmt_date("0") == "" and fmt_date(None) == "" and fmt_date("") == ""
    assert fmt_date("2026-10-25T06:00:00Z") == "2026-10-25T06:00:00Z"


def test_record_to_row(dataset):
    rec = next(r for r in dataset["records"] if r["severity"]["name"] == "Critical")
    row = sc_record_to_row(rec)
    assert list(row) == HEADERS
    assert row["Plugin"] == rec["pluginID"] and row["Severity"] == "Critical" and row["Repository"] == rec["repository"]["name"]
    assert row["Exploit?"] in ("Yes", "No") and ISO.match(row["First Discovered"]) and ISO.match(row["Last Observed"])
    assert row["Steps to Remediate"] == rec["solution"] and row["Plugin Text"] == rec["pluginText"]


def test_pull_writes_the_two_exports_and_the_manifest(cfg, dataset, mock_sc):
    store = ExportStore(cfg.store.dir)
    m = pull_security_center(cfg, store, PullProgress("test"))
    expect = dataset_counts(dataset)
    assert m["status"] == "ok" and m["source"]["version"] == "6.9.0" and m["source"]["user"] == "studio.api"
    kinds = {f["kind"]: f for f in m["files"]}
    assert kinds["va"]["rows"] == expect["va_rows"] and kinds["va"]["hosts"] == expect["va_hosts"]
    assert kinds["compliance"]["rows"] == expect["cmp_rows"] and kinds["compliance"]["hosts"] == expect["cmp_hosts"]
    assert kinds["va"]["severity"] == expect["severity"]
    # rows stored in two repositories are distinct keys; the only rows returned twice are the failed / warning compliance checks,
    # which the vulnerability query (every type, severities 1-4) and the compliance query both return
    twice = len({(r["pluginID"], r["ip"], r["port"], r["protocol"], r["repository"]["id"], r["pluginName"]) for r in dataset["records"] if r["family"]["type"] == "compliance" and r["severity"]["name"] != "Info"})
    assert m["counts"]["duplicates_skipped"] == twice
    assert m["risk_rules"] == {"accept": 2, "recast": 1}
    assert len(m["scans"]) == 4 and m["scans"][0]["finishTime"] >= m["scans"][-1]["finishTime"]
    # the files are gzip with a BOM and the exact header line
    va_path = Path(cfg.store.dir) / m["id"] / kinds["va"]["name"]
    assert va_path.name.endswith(".csv.gz")
    with gzip.open(va_path, "rt", encoding="utf-8", newline="") as fh:
        first = fh.readline()
    assert first.startswith("﻿") and first.rstrip("\r\n").lstrip("﻿").split(",")[:5] == ["Plugin", "Plugin Name", "Family", "Severity", "IP Address"]
    # paging actually happened (page size 300 against >300 rows)
    calls = mock_sc.app.state.calls
    assert sum(1 for c in calls if c["query"]["filters"][0]["value"] == "4,3,2,1") >= 2
    # the inventory query carries the inventory plugin ids and severity 0
    inv = next(c for c in calls if any(f["filterName"] == "pluginID" for f in c["query"]["filters"]))
    assert {f["filterName"]: f["value"] for f in inv["query"]["filters"]}["severity"] == "0"
    # routing: compliance rows only in the compliance file, inventory rows in the VA file
    va_rows = read_export(store, m["id"], kinds["va"]["name"])
    cmp_rows = read_export(store, m["id"], kinds["compliance"]["name"])
    assert all(int(r["Plugin"]) < 1_000_000 for r in va_rows) and all(int(r["Plugin"]) >= 1_000_000 for r in cmp_rows)
    assert any(r["Plugin"] == "11936" and r["Severity"] == "Info" for r in va_rows), "OS identification rows keep the hosts listed"
    assert any("Result: FAILED" in r["Plugin Text"] for r in cmp_rows)
    assert all(ISO.match(r["Last Observed"]) for r in va_rows)
    # the manifest on disk
    on_disk = json.loads((Path(cfg.store.dir) / m["id"] / "manifest.json").read_text())
    assert on_disk["summary"] == m["summary"] and "vulnerability rows" in on_disk["summary"]
    assert store.latest()["id"] == m["id"]


def test_invalid_filter_is_dropped_and_retried(cfg, dataset, tmp_path):
    """An older Security Center that rejects wasVuln must not stop the pull."""
    from trs_connector.mock_sc import create_mock_app
    from tests.conftest import ServerThread, free_port
    app = create_mock_app(dataset, "AK", "SK", reject_filters=("wasVuln",))

    @app.get("/healthz")
    async def hz():
        return {"ok": True}
    srv = ServerThread(app, free_port()).start()
    try:
        cfg.sc.url = f"http://127.0.0.1:{srv.port}"
        cfg.store.dir = str(tmp_path / "d2")
        m = pull_security_center(cfg, ExportStore(cfg.store.dir), PullProgress("test"))
        assert m["status"] == "ok" and m["files"][0]["rows"] == dataset_counts(dataset)["va_rows"]
    finally:
        srv.stop()


def test_bad_keys_fail_cleanly(cfg, tmp_path):
    cfg.sc.secret_key = "wrong"
    store = ExportStore(str(tmp_path / "d3"))
    with pytest.raises(SCError) as e:
        pull_security_center(cfg, store, PullProgress("test"))
    assert "403" in str(e.value)
    failed = store.list_pulls(include_failed=True)
    assert failed and failed[0]["status"] == "failed" and store.list_pulls() == []


def test_repository_filter(cfg, dataset, tmp_path):
    cfg.sc.repositories = ["Compliance Repository"]
    store = ExportStore(str(tmp_path / "d4"))
    m = pull_security_center(cfg, store, PullProgress("test"))
    rows = read_export(store, m["id"], m["files"][0]["name"])
    assert rows and all(r["Repository"] == "Compliance Repository" for r in rows)
    assert [r["name"] for r in m["source"]["repositories"]] == ["Compliance Repository"]


def test_unknown_repository_is_an_error(cfg, tmp_path):
    cfg.sc.repositories = ["Nope"]
    with pytest.raises(SCError, match="Nope"):
        pull_security_center(cfg, ExportStore(str(tmp_path / "d5")), PullProgress("test"))


def test_client_pagination_stops_on_short_page(cfg):
    with SecurityCenterClient(cfg.sc.url, "AK", "SK", verify=False, timeout=30) as c:
        seen = list(c.iter_analysis({"filters": [{"filterName": "severity", "operator": "=", "value": "4"}]}, page_size=50))
        page = c.analysis_page({"type": "vuln", "tool": "vulndetails", "filters": [{"filterName": "severity", "operator": "=", "value": "4"}]}, 0, 1)
        assert len(seen) == int(page["totalRecords"]) and all(r["severity"]["name"] == "Critical" for r in seen)
