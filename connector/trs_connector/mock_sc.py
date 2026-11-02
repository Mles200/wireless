"""A small Tenable Security Center look-alike for the tests and the demo: API-key header, the
JSON envelope, the analysis endpoint with filters and paging, repositories, risk rules and
scan results.  It serves a dataset from ``synth.py``.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

VALID_FILTERS = ["repository", "severity", "pluginID", "pluginType", "wasVuln", "ip", "lastSeen", "firstSeen", "exploitAvailable", "family", "port", "protocol", "acceptRiskStatus", "recastRiskStatus"]


def envelope(response: Any) -> dict:
    return {"type": "regular", "response": response, "error_code": 0, "error_msg": "", "warnings": [], "timestamp": int(time.time())}


def error(code: int, msg: str, status: int = 403) -> JSONResponse:
    return JSONResponse({"type": "regular", "response": "", "error_code": code, "error_msg": msg, "warnings": [], "timestamp": int(time.time())}, status_code=status)


def create_mock_app(data: dict, access_key: str = "ak", secret_key: str = "sk", reject_filters: tuple = (), max_page: int = 100000) -> FastAPI:
    app = FastAPI(title="mock Security Center")
    app.state.data = data
    app.state.calls: list[dict] = []
    rejected = set(reject_filters)

    @app.middleware("http")
    async def auth(request: Request, call_next):
        hdr = request.headers.get("x-apikey", "")
        pairs = dict(p.strip().split("=", 1) for p in hdr.split(";") if "=" in p)
        if pairs.get("accessKey") != access_key or pairs.get("secretKey") != secret_key:
            return error(2, "Invalid API key", 403)
        return await call_next(request)

    @app.get("/rest/system")
    async def system():
        return envelope(data["system"])

    @app.get("/rest/currentUser")
    async def current_user():
        return envelope(data["user"])

    @app.get("/rest/repository")
    async def repository():
        return envelope(data["repositories"])

    @app.get("/rest/acceptRiskRule")
    async def accept_rules():
        return envelope(data["accept_rules"])

    @app.get("/rest/recastRiskRule")
    async def recast_rules():
        return envelope(data["recast_rules"])

    @app.get("/rest/scanResult")
    async def scan_results(startTime: str = "0"):
        since = int(startTime or 0)
        return envelope([s for s in data["scans"] if int(s["finishTime"]) >= since])

    @app.post("/rest/analysis")
    async def analysis(request: Request):
        body = await request.json()
        app.state.calls.append(body)
        q = body.get("query") or {}
        if body.get("type") != "vuln" or q.get("tool") != "vulndetails":
            return error(146, "Invalid parameters specified for vuln query: unsupported tool")
        filters = q.get("filters") or []
        for f in filters:
            name = f.get("filterName")
            if name not in VALID_FILTERS or name in rejected:
                return error(146, f"Invalid parameters specified for vuln query.  The filter '{name}' is invalid (valid filters: {', '.join(x for x in VALID_FILTERS if x not in rejected)}).")
        rows = list(data["records"])
        for f in filters:
            name, value = f.get("filterName"), f.get("value")
            if name == "severity":
                ids = set(str(v).strip() for v in str(value).split(","))
                rows = [r for r in rows if r["severity"]["id"] in ids]
            elif name == "pluginType":
                rows = [r for r in rows if r["family"]["type"] == value] if value != "all" else rows
            elif name == "pluginID":
                ids = set(str(v).strip() for v in str(value).split(","))
                rows = [r for r in rows if r["pluginID"] in ids]
            elif name == "repository":
                ids = set(str(v.get("id")) for v in value) if isinstance(value, list) else {str(value)}
                rows = [r for r in rows if r["repository"]["id"] in ids]
            elif name == "ip":
                rows = [r for r in rows if r["ip"] == value]
        sort_field = body.get("sortField")
        if sort_field:
            rows.sort(key=lambda r: str(r.get(sort_field, "")), reverse=str(body.get("sortDir", "ASC")).upper() == "DESC")
        start = int(q.get("startOffset", 0))
        end = min(int(q.get("endOffset", start + 200)), start + max_page)
        page = rows[start:end]
        return envelope({"totalRecords": str(len(rows)), "returnedRecords": len(page), "startOffset": str(start), "endOffset": str(end), "matchingDataElementCount": str(len(rows)), "results": page})

    return app
