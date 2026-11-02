"""The HTTP service: the Studio at /, the Tenable panel script at /connector.js and the API
under /api.  Everything except /healthz is behind HTTP basic authentication when a username
and password are configured.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

from . import __version__
from .config import Config
from .exporter import PullRunner
from .sc_client import SCError, SecurityCenterClient
from .scheduler import Scheduler
from .store import ExportStore

log = logging.getLogger(__name__)
STATIC = Path(__file__).resolve().parent / "static"
VERSION_RE = re.compile(r"STUDIO_VERSION\s*=\s*'([\d.]+)'")


class StudioAssets:
    """The Studio HTML with the connector script tag injected before </body>; re-read when the
    file changes on disk so a new Studio version is picked up without a restart."""

    def __init__(self, path: Path):
        self.path = path
        self._mtime = 0.0
        self._html = ""
        self.version = ""

    def html(self) -> str:
        try:
            mtime = self.path.stat().st_mtime
        except OSError as e:
            raise HTTPException(503, f"The Studio file is not available: {self.path} ({e})") from e
        if mtime != self._mtime or not self._html:
            src = self.path.read_text(encoding="utf-8")
            m = VERSION_RE.search(src)
            self.version = m.group(1) if m else "?"
            tag = f'<script src="connector.js?v={__version__}" data-trs-connector="1"></script>\n'
            at = src.rfind("</body>")
            self._html = (src[:at] + tag + src[at:]) if at >= 0 else src + tag
            self._mtime = mtime
        return self._html


def create_app(cfg: Config) -> FastAPI:
    store = ExportStore(cfg.store.dir)
    runner = PullRunner(cfg, store)
    scheduler = Scheduler(cfg, runner)
    studio = StudioAssets(cfg.studio_path)
    connector_js = (STATIC / "connector.js").read_text(encoding="utf-8")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        scheduler.start()
        log.info("Tenable Report Studio connector %s serving %s from %s", __version__, studio.path.name, cfg.store.dir)
        if not (cfg.server.auth.username and cfg.server.auth.password):
            log.warning("no server.auth username/password configured: the Studio and the exports are open to anyone who can reach port %s", cfg.server.port)
        if cfg.sc.enabled and cfg.sc.verify is False:
            log.warning("sc.verify is false: the Security Center certificate is not verified")
        try:
            yield
        finally:
            scheduler.stop()

    app = FastAPI(title="Tenable Report Studio connector", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.cfg, app.state.store, app.state.runner, app.state.scheduler, app.state.studio = cfg, store, runner, scheduler, studio

    # ---- authentication --------------------------------------------------------------------
    user, pwd = cfg.server.auth.username or "", cfg.server.auth.password or ""

    @app.middleware("http")
    async def basic_auth(request: Request, call_next):
        if user and pwd and request.url.path != "/healthz":
            header = request.headers.get("authorization", "")
            ok = False
            if header.lower().startswith("basic "):
                try:
                    raw = base64.b64decode(header[6:]).decode("utf-8")
                    u, _, p = raw.partition(":")
                    ok = secrets.compare_digest(u.encode(), user.encode()) and secrets.compare_digest(p.encode(), pwd.encode())
                except Exception:   # noqa: BLE001
                    ok = False
            if not ok:
                return Response("Authentication required", 401, headers={"WWW-Authenticate": 'Basic realm="Tenable Report Studio"'})
        resp = await call_next(request)
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    # ---- the Studio ------------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/studio", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/studio.html", response_class=HTMLResponse, include_in_schema=False)
    async def studio_page():
        return HTMLResponse(studio.html())

    @app.get("/connector.js", include_in_schema=False)
    async def connector_script():
        return Response(connector_js, media_type="application/javascript; charset=utf-8")

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"ok": True, "version": __version__, "time": time.time()}

    # ---- status and pulls -----------------------------------------------------------------
    def source_info() -> dict:
        if cfg.sc.enabled:
            return {"type": "sc", "label": "Tenable Security Center", "url": cfg.sc.url, "configured": bool(cfg.sc.url and cfg.sc.access_key and cfg.sc.secret_key), "verify": cfg.sc.verify}
        return {"type": "nessus", "label": "Nessus", "url": cfg.nessus.url, "configured": bool(cfg.nessus.url and cfg.nessus.access_key and cfg.nessus.secret_key), "verify": cfg.nessus.verify}

    def manifest_summary(m: dict) -> dict:
        return {k: m.get(k) for k in ("id", "status", "started", "finished", "duration_s", "trigger", "summary", "warnings", "risk_rules", "counts", "error")} | {
            "source": {k: (m.get("source") or {}).get(k) for k in ("type", "url", "version", "user", "organization")},
            "repositories": [r.get("name") for r in (m.get("source") or {}).get("repositories", [])],
            "files": [{k: f.get(k) for k in ("name", "display_name", "kind", "rows", "hosts", "severity", "bytes")} for f in m.get("files", [])],
            "scans": len(m.get("scans") or []), "has_scans": "scans" in m, "has_rules": "risk_rules" in m}

    @app.get("/api/status")
    async def status():
        latest = store.latest()
        return {"connector": {"version": __version__, "time": time.time(), "config": cfg.source_path or None, "auth": bool(user and pwd)},
                "source": source_info(), "store": store.stats(), "latest": manifest_summary(latest) if latest else None,
                "job": runner.status(), "schedule": scheduler.describe(),
                "studio": {"version": studio.version or (studio.html() and studio.version), "file": studio.path.name, "shared_state": cfg.studio.shared_state, "org": cfg.studio.org}}

    @app.post("/api/pull", status_code=202)
    async def start_pull(request: Request):
        body = {}
        try:
            body = await request.json()
        except Exception:   # noqa: BLE001
            body = {}
        source = (body or {}).get("source")
        if source not in (None, "sc", "nessus"):
            raise HTTPException(400, "source must be sc or nessus")
        if source == "sc" and not cfg.sc.enabled or source == "nessus" and not cfg.nessus.enabled:
            raise HTTPException(400, f"source {source} is not enabled in the configuration")
        try:
            p = runner.start("manual", source)
        except RuntimeError as e:
            raise HTTPException(409, str(e)) from e
        return p.to_dict()

    @app.get("/api/jobs")
    async def jobs():
        return [p.to_dict() for p in reversed(runner.history)]

    @app.get("/api/jobs/{job_id}")
    async def job(job_id: str):
        p = runner.find(job_id)
        if not p:
            raise HTTPException(404, "no such job")
        return p.to_dict()

    @app.get("/api/exports")
    async def exports(include_failed: bool = False):
        return [manifest_summary(m) for m in store.list_pulls(include_failed=include_failed)]

    @app.get("/api/exports/{pull_id}")
    async def export_manifest(pull_id: str):
        try:
            m = store.manifest(pull_id)
        except KeyError:
            m = None
        if not m:
            raise HTTPException(404, "no such pull")
        return m

    @app.get("/api/exports/{pull_id}/files/{name}")
    async def export_file(pull_id: str, name: str, download: int = 0):
        try:
            path = store.file_path(pull_id, name)
        except KeyError:
            raise HTTPException(404, "no such file") from None
        display = path.name[:-3] if path.name.endswith(".gz") else path.name
        headers = {"Content-Disposition": f'{"attachment" if download else "inline"}; filename="{display}"', "X-Export-File": display}
        media = "text/csv; charset=utf-8" if display.endswith(".csv") else "application/json"
        if path.name.endswith(".gz"):
            headers["Content-Encoding"] = "gzip"
        return FileResponse(path, media_type=media, headers=headers)

    @app.get("/api/exports/{pull_id}/risk-rules")
    async def export_rules(pull_id: str):
        try:
            return store.read_json(pull_id, "risk-rules.json")
        except KeyError:
            raise HTTPException(404, "this pull has no risk rules file") from None

    @app.get("/api/exports/{pull_id}/scans")
    async def export_scans(pull_id: str):
        try:
            return store.read_json(pull_id, "scans.json")
        except KeyError:
            raise HTTPException(404, "this pull has no scans file") from None

    @app.delete("/api/exports/{pull_id}")
    async def delete_export(pull_id: str):
        try:
            store.delete(pull_id)
        except KeyError:
            raise HTTPException(404, "no such pull") from None
        return {"deleted": pull_id}

    # ---- live Security Center reads ----------------------------------------------------------
    def sc_client() -> SecurityCenterClient:
        if not cfg.sc.enabled:
            raise HTTPException(400, "Security Center is not enabled in the configuration")
        try:
            return SecurityCenterClient(cfg.sc.url, cfg.sc.access_key, cfg.sc.secret_key, verify=cfg.sc.verify, timeout=min(cfg.sc.timeout, 60))
        except SCError as e:
            raise HTTPException(503, str(e)) from e

    @app.get("/api/tenable/check")
    async def tenable_check():
        if not cfg.sc.enabled and cfg.nessus.enabled:
            from .nessus_source import nessus_check
            try:
                return nessus_check(cfg)
            except Exception as e:   # noqa: BLE001
                raise HTTPException(503, str(e)) from e
        try:
            with sc_client() as c:
                system = c.system()
                repos = c.repositories()
                try:
                    u = c.current_user()
                except SCError:
                    u = {}
            return {"ok": True, "type": "sc", "url": cfg.sc.url, "version": system.get("version"), "build": system.get("buildID"), "license": system.get("licenseStatus"),
                    "user": u.get("username"), "repositories": [{"id": r.get("id"), "name": r.get("name"), "type": r.get("type")} for r in repos], "checked": time.time()}
        except SCError as e:
            raise HTTPException(503, str(e)) from e

    @app.get("/api/tenable/risk-rules")
    async def tenable_rules():
        try:
            with sc_client() as c:
                return {"accept": c.accept_risk_rules(), "recast": c.recast_risk_rules(), "fetched": time.time()}
        except SCError as e:
            raise HTTPException(503, str(e)) from e

    @app.get("/api/tenable/scans")
    async def tenable_scans(days: int = 45):
        try:
            with sc_client() as c:
                return {"days": days, "results": c.scan_results(days)}
        except SCError as e:
            raise HTTPException(503, str(e)) from e

    # ---- shared state: report settings and the risk register ----------------------------------
    def state_enabled() -> None:
        if not cfg.studio.shared_state:
            raise HTTPException(404, "shared state is disabled (studio.shared_state)")

    @app.get("/api/state/{name}")
    async def get_state(name: str):
        state_enabled()
        if name not in ("settings", "register"):
            raise HTTPException(404, "unknown state")
        data = store.read_state(f"{name}.json")
        if data is None:
            return JSONResponse({"present": False}, status_code=200)
        return data

    @app.put("/api/state/{name}")
    async def put_state(name: str, request: Request):
        state_enabled()
        if name not in ("settings", "register"):
            raise HTTPException(404, "unknown state")
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(400, "the body must be JSON") from None
        if not isinstance(body, dict):
            raise HTTPException(400, "the body must be a JSON object")
        if len(json.dumps(body)) > 50_000_000:
            raise HTTPException(413, "too large")
        base = body.pop("if_server_updated", None)
        if base is not None:   # optimistic concurrency for the register: refuse to overwrite a newer copy
            current = store.read_state(f"{name}.json")
            if current and abs(float(current.get("server_updated") or 0) - float(base or 0)) > 1e-6:
                return JSONResponse({"detail": "the server copy changed since it was loaded", "server_updated": current.get("server_updated")}, status_code=409)
        body["present"] = True
        body["server_updated"] = time.time()
        body["updated_by"] = request.client.host if request.client else ""
        store.write_state(f"{name}.json", body)
        return {"ok": True, "server_updated": body["server_updated"]}

    @app.get("/api/config", response_class=PlainTextResponse, include_in_schema=False)
    async def show_config():
        """The configuration in force, secrets masked."""
        import dataclasses
        d = dataclasses.asdict(cfg)
        for sect in ("sc", "nessus"):
            for k in ("access_key", "secret_key"):
                if d[sect].get(k):
                    d[sect][k] = "***"
        if d["server"]["auth"].get("password"):
            d["server"]["auth"]["password"] = "***"
        return json.dumps(d, indent=1)

    return app
