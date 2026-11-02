"""The Python client never hammers Security Center: one request at a time, a pause between
requests, backoff on 429 with Retry-After, and a clean failure when the retries are exhausted."""
from __future__ import annotations

import time

import pytest

from trs_connector.mock_sc import create_mock_app
from trs_connector.sc_client import SCError, SecurityCenterClient

from tests.conftest import ServerThread, free_port


def serve(app):
    @app.get("/healthz")
    async def hz():
        return {"ok": True}
    srv = ServerThread(app, free_port()).start()
    srv.app = app
    return srv


def test_requests_are_spaced(dataset):
    srv = serve(create_mock_app(dataset, "AK", "SK"))
    try:
        with SecurityCenterClient(f"http://127.0.0.1:{srv.port}", "AK", "SK", request_interval=0.3, retries=0, timeout=30) as c:
            t0 = time.monotonic()
            c.system(); c.system(); c.system()
            elapsed = time.monotonic() - t0
        assert elapsed >= 0.6, f"three requests took only {elapsed:.2f} s: the 0.3 s pause was not applied"
        assert c.pacer.stats["requests"] == 3 and c.pacer.stats["waited_s"] >= 0.5
    finally:
        srv.stop()


def test_429_is_retried_with_backoff(dataset):
    srv = serve(create_mock_app(dataset, "AK", "SK", rate_limit_every=4))
    try:
        with SecurityCenterClient(f"http://127.0.0.1:{srv.port}", "AK", "SK", request_interval=0.02, retries=3, timeout=30) as c:
            rows = list(c.iter_analysis({"filters": [{"filterName": "severity", "operator": "=", "value": "4,3"}]}, page_size=25))
            page = c.analysis_page({"type": "vuln", "tool": "vulndetails", "filters": [{"filterName": "severity", "operator": "=", "value": "4,3"}]}, 0, 1)
        assert len(rows) == int(page["totalRecords"])
        assert srv.app.state.rate_limited >= 2 and c.pacer.stats["retries"] >= 2
        assert "retries" in c.pacer.describe()
    finally:
        srv.stop()


def test_retries_exhausted_is_a_clean_error(dataset):
    srv = serve(create_mock_app(dataset, "AK", "SK", rate_limit_every=1))   # every analysis call is refused
    try:
        with SecurityCenterClient(f"http://127.0.0.1:{srv.port}", "AK", "SK", request_interval=0.0, retries=2, timeout=30) as c:
            with pytest.raises(SCError, match="429"):
                list(c.iter_analysis({"filters": []}, page_size=10))
        assert c.pacer.stats["requests"] == 3 and c.pacer.stats["retries"] == 2
    finally:
        srv.stop()
