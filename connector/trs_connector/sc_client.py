"""Tenable Security Center REST client (the parts the connector needs).

Authentication uses API keys (Security Center 5.13 and later): the header
``X-APIKey: accessKey=...; secretKey=...`` on every request, no session.  The analysis endpoint
is paged with startOffset / endOffset exactly as the Security Center UI and pyTenable do.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Iterator

import httpx

log = logging.getLogger(__name__)


class SCError(Exception):
    """An error reported by Security Center (HTTP status or error_code in the JSON envelope)."""

    def __init__(self, message: str, status: int | None = None, code: int | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


INVALID_FILTER_RE = re.compile(r"The filter '([^']+)' is invalid")


class SecurityCenterClient:
    def __init__(self, url: str, access_key: str, secret_key: str, verify: bool | str = False, timeout: float = 600.0):
        if not url:
            raise SCError("Security Center URL is not configured")
        if not access_key or not secret_key:
            raise SCError("Security Center API keys are not configured (sc.access_key / sc.secret_key or TRS_SC_ACCESS_KEY / TRS_SC_SECRET_KEY)")
        base = url.rstrip("/")
        if not base.endswith("/rest"):
            base += "/rest"
        self.base = base + "/"
        self._http = httpx.Client(
            base_url=self.base,
            headers={"X-APIKey": f"accessKey={access_key}; secretKey={secret_key}", "Accept": "application/json"},
            verify=verify, timeout=timeout, follow_redirects=False,
        )

    # ---- plumbing ---------------------------------------------------------------------------
    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _call(self, method: str, path: str, **kw) -> Any:
        try:
            resp = self._http.request(method, path.lstrip("/"), **kw)
        except httpx.HTTPError as e:
            raise SCError(f"{method} {path}: {e.__class__.__name__}: {e}") from e
        if resp.status_code in (401, 403):
            raise SCError(f"{method} {path}: HTTP {resp.status_code} (check the API keys and the user's permissions): {resp.text[:300]}", resp.status_code)
        if resp.status_code >= 400:
            raise SCError(f"{method} {path}: HTTP {resp.status_code}: {resp.text[:300]}", resp.status_code)
        try:
            data = resp.json()
        except ValueError as e:
            raise SCError(f"{method} {path}: the response is not JSON (is this the Security Center URL? got {resp.headers.get('content-type')})") from e
        if isinstance(data, dict) and data.get("error_code"):
            raise SCError(f"{method} {path}: {data.get('error_msg') or 'error'} (error_code {data['error_code']})", resp.status_code, int(data["error_code"]))
        return data.get("response") if isinstance(data, dict) else data

    def get(self, path: str, params: dict | None = None) -> Any:
        return self._call("GET", path, params=params)

    def post(self, path: str, json: Any) -> Any:
        return self._call("POST", path, json=json)

    # ---- simple reads -------------------------------------------------------------------------
    def system(self) -> dict:
        return self.get("system") or {}

    def current_user(self) -> dict:
        return self.get("currentUser", {"fields": "id,username,firstname,lastname,role,organization"}) or {}

    def repositories(self) -> list[dict]:
        return self.get("repository", {"fields": "id,name,description,type,dataFormat"}) or []

    def accept_risk_rules(self) -> list[dict]:
        return self.get("acceptRiskRule", {"fields": "id,hostType,hostValue,port,protocol,expires,status,comments,createdTime,modifiedTime,plugin,repository,user"}) or []

    def recast_risk_rules(self) -> list[dict]:
        return self.get("recastRiskRule", {"fields": "id,hostType,hostValue,port,protocol,newSeverity,status,comments,createdTime,modifiedTime,plugin,repository,user"}) or []

    def scan_results(self, days: int = 45) -> list[dict]:
        since = int(time.time()) - days * 86400
        params = {"fields": "id,name,status,startTime,finishTime,scannedIPs,totalIPs,completedIPs,importStatus,importStart,importFinish,totalChecks,repository,scanDuration",
                  "optimizeCompletedScanResults": "true", "startTime": str(since)}
        results = self.get("scanResult", params) or []
        if isinstance(results, dict):   # some versions wrap the list as {"usable": [...], "manageable": [...]}
            results = results.get("usable") or results.get("manageable") or []
        return results

    # ---- analysis -----------------------------------------------------------------------------
    def analysis_page(self, query: dict, start: int, limit: int, sort_field: str = "", source_type: str = "cumulative") -> dict:
        q = dict(query)
        q["startOffset"] = start
        q["endOffset"] = start + limit
        payload: dict[str, Any] = {"type": q.get("type", "vuln"), "sourceType": source_type, "query": q}
        if sort_field:
            payload["sortField"] = sort_field
            payload["sortDir"] = "ASC"
        return self.post("analysis", payload) or {}

    def iter_analysis(self, query: dict, page_size: int = 2500, sort_field: str = "", progress: Callable[[int, int | None], None] | None = None) -> Iterator[dict]:
        """Yield every record of a vulnerability analysis query, page by page.

        A filter the installed version does not know (error 146 "The filter 'x' is invalid")
        is dropped with a warning and the query retried, so an optional filter such as
        ``wasVuln`` does not stop the pull on an older Security Center.
        """
        query = {"type": "vuln", "tool": "vulndetails", **query}
        start = 0
        total: int | None = None
        while True:
            try:
                page = self.analysis_page(query, start, page_size, sort_field)
            except SCError as e:
                m = INVALID_FILTER_RE.search(str(e))
                if m and any(f.get("filterName") == m.group(1) for f in query.get("filters", [])):
                    log.warning("Security Center does not accept the filter %r; retrying without it", m.group(1))
                    query["filters"] = [f for f in query["filters"] if f.get("filterName") != m.group(1)]
                    continue
                raise
            results = page.get("results") or []
            try:
                total = int(page.get("totalRecords")) if page.get("totalRecords") not in (None, "") else total
            except (TypeError, ValueError):
                pass
            for rec in results:
                yield rec
            start += len(results)
            if progress:
                progress(start, total)
            if not results or len(results) < page_size or (total is not None and start >= total):
                break


def vuln_filters(severities: str, repositories: list[dict] | None = None, plugin_type: str | None = None, plugin_ids: list[int] | None = None,
                 extra: list[dict] | None = None, exclude_was: bool = True) -> list[dict]:
    """The filter list of a vulndetails query, in the shape Security Center expects."""
    filters: list[dict] = []
    if severities:
        filters.append({"filterName": "severity", "operator": "=", "value": severities})
    if repositories:
        filters.append({"filterName": "repository", "operator": "=", "value": [{"id": str(r["id"])} for r in repositories]})
    if plugin_type:
        filters.append({"filterName": "pluginType", "operator": "=", "value": plugin_type})
    if plugin_ids:
        filters.append({"filterName": "pluginID", "operator": "=", "value": ",".join(str(p) for p in plugin_ids)})
    if exclude_was:
        filters.append({"filterName": "wasVuln", "operator": "=", "value": "excludeWas"})
    for f in extra or []:
        if isinstance(f, dict) and f.get("filterName"):
            filters.append({"filterName": f["filterName"], "operator": f.get("operator", "="), "value": f.get("value", "")})
    return filters


def resolve_repositories(wanted: list, available: list[dict]) -> list[dict]:
    """Map the configured repository names or ids onto the repositories Security Center lists."""
    if not wanted:
        return []
    out = []
    for w in wanted:
        hit = next((r for r in available if str(r.get("id")) == str(w) or str(r.get("name", "")).strip().lower() == str(w).strip().lower()), None)
        if not hit:
            raise SCError(f"repository {w!r} is not in Security Center (available: {', '.join(str(r.get('name')) for r in available)})")
        out.append(hit)
    return out
