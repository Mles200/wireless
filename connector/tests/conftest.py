"""Shared fixtures: a synthetic dataset, a mock Security Center served in a thread, and a
connector configured against it with a temporary store."""
from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from trs_connector.config import Config
from trs_connector.mock_sc import create_mock_app
from trs_connector.synth import SynthOptions, synth_dataset

ROOT = Path(__file__).resolve().parents[2]
STUDIO = ROOT / "studio" / "ALTANFEETHI_Tenable_Report_Studio.html"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread:
    def __init__(self, app, port: int):
        self.port = port
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        for _ in range(200):
            try:
                httpx.get(f"http://127.0.0.1:{self.port}/healthz", timeout=1)
                return self
            except httpx.HTTPError:
                time.sleep(0.05)
        raise RuntimeError("server did not start")

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture(scope="session")
def dataset():
    return synth_dataset(SynthOptions(hosts=40, seed=3))


@pytest.fixture(scope="session")
def mock_sc(dataset):
    app = create_mock_app(dataset, access_key="AK", secret_key="SK")

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    srv = ServerThread(app, free_port()).start()
    srv.app = app
    yield srv
    srv.stop()


@pytest.fixture()
def cfg(mock_sc, tmp_path) -> Config:
    c = Config()
    c.sc.url = f"http://127.0.0.1:{mock_sc.port}"
    c.sc.access_key, c.sc.secret_key = "AK", "SK"
    c.sc.page_size = 300           # several pages
    c.sc.compliance_page_size = 150
    c.sc.request_interval = 0.05   # the pacing itself is tested in test_pacing.py; keep the other tests quick
    c.store.dir = str(tmp_path / "data")
    c.schedule.enabled = False
    c.studio.path = str(STUDIO)
    c.server.auth.username, c.server.auth.password = "studio", "secret"
    return c
