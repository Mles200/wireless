"""Nessus / Nessus Manager (port 8834) as the data source.

The Nessus API has no cumulative view: the connector exports the completed scans (``.nessus``
XML, format "nessus"), turns every ReportItem into a record with the Security Center field
names and routes it through the same export writer as a Security Center pull.  Nessus does not
know when a finding was first seen, so First Discovered is carried forward from the previous
Nessus pull in the store (the earliest Last Observed the connector has seen for that plugin,
host, port and protocol).
"""
from __future__ import annotations

import io
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree as ET

import httpx

from . import __version__
from .config import Config
from .export_schema import dedup_key, is_compliance, sc_record_to_row
from .exporter import PullProgress, summarize
from .store import ExportStore, ExportWriter, csv_rows

log = logging.getLogger(__name__)
CM = "{http://www.nessus.org/cm}"
SEVERITY_NAMES = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}


class NessusError(Exception):
    pass


class NessusClient:
    def __init__(self, url: str, access_key: str, secret_key: str, verify: bool | str = False, timeout: float = 600.0):
        if not url:
            raise NessusError("Nessus URL is not configured")
        if not access_key or not secret_key:
            raise NessusError("Nessus API keys are not configured (nessus.access_key / nessus.secret_key)")
        self._http = httpx.Client(base_url=url.rstrip("/") + "/", headers={"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}", "Accept": "application/json"}, verify=verify, timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _req(self, method: str, path: str, **kw) -> httpx.Response:
        try:
            resp = self._http.request(method, path.lstrip("/"), **kw)
        except httpx.HTTPError as e:
            raise NessusError(f"{method} {path}: {e.__class__.__name__}: {e}") from e
        if resp.status_code in (401, 403):
            raise NessusError(f"{method} {path}: HTTP {resp.status_code} (check the API keys): {resp.text[:200]}")
        if resp.status_code >= 400:
            raise NessusError(f"{method} {path}: HTTP {resp.status_code}: {resp.text[:200]}")
        return resp

    def get_json(self, path: str, params: dict | None = None) -> dict:
        return self._req("GET", path, params=params).json()

    def post_json(self, path: str, json: dict | None = None) -> dict:
        r = self._req("POST", path, json=json)
        return r.json() if r.content else {}

    def properties(self) -> dict:
        return self.get_json("server/properties")

    def status(self) -> dict:
        return self.get_json("server/status")

    def scans(self, folder_id: int | None = None) -> dict:
        return self.get_json("scans", {"folder_id": folder_id} if folder_id else None)

    def scan_details(self, scan_id: int) -> dict:
        return self.get_json(f"scans/{scan_id}")

    def export_nessus(self, scan_id: int, poll: float = 2.0, max_wait: float = 3600.0) -> bytes:
        token = self.post_json(f"scans/{scan_id}/export", {"format": "nessus"})
        file_id = token.get("file")
        if not file_id:
            raise NessusError(f"scan {scan_id}: export did not return a file id ({token})")
        waited = 0.0
        while True:
            st = self.get_json(f"scans/{scan_id}/export/{file_id}/status")
            if st.get("status") == "ready":
                break
            if st.get("status") in ("error", "cancelled"):
                raise NessusError(f"scan {scan_id}: export {st.get('status')}")
            time.sleep(poll)
            waited += poll
            if waited > max_wait:
                raise NessusError(f"scan {scan_id}: export not ready after {max_wait:.0f} s")
        return self._req("GET", f"scans/{scan_id}/export/{file_id}/download").content


# ---- .nessus parsing -----------------------------------------------------------------------------
def _text(el, tag: str) -> str:
    x = el.find(tag)
    return (x.text or "").strip() if x is not None else ""


def _texts(el, tag: str) -> str:
    return ", ".join((x.text or "").strip() for x in el.findall(tag) if (x.text or "").strip())


def _date(s: str) -> str:
    """Nessus dates ('Thu Oct 24 06:12:33 2026', '2024/10/08', epoch) -> epoch seconds as text."""
    s = (s or "").strip()
    if not s:
        return ""
    if s.isdigit():
        return s
    for fmt in ("%a %b %d %H:%M:%S %Y", "%Y/%m/%d", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return str(int(datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()))
        except ValueError:
            continue
    return ""


def parse_nessus(source: bytes | str | Path, repository_name: str) -> Iterator[dict]:
    """Yield Security-Center-shaped records for every ReportItem of a .nessus file."""
    if isinstance(source, (str, Path)):
        stream = open(source, "rb")
    else:
        stream = io.BytesIO(source)
    try:
        host_props: dict[str, str] = {}
        host_name = ""
        for event, el in ET.iterparse(stream, events=("start", "end")):
            if event == "start" and el.tag == "ReportHost":
                host_name = el.get("name", "")
                host_props = {}
            elif event == "end" and el.tag == "HostProperties":
                host_props = {t.get("name", ""): (t.text or "").strip() for t in el.findall("tag")}
            elif event == "end" and el.tag == "ReportItem":
                yield _item_record(el, host_name, host_props, repository_name)
                el.clear()
            elif event == "end" and el.tag == "ReportHost":
                el.clear()
    finally:
        stream.close()


IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def compliance_plugin_id(check_name: str, audit_file: str = "") -> int:
    """A stable plugin ID for a compliance check, in the range Security Center uses for its own
    compliance plugins (1,000,000 and up).  Nessus reports every check of an audit under one
    plugin ID (21156 for Windows, 21157 for Unix), but the Studio identifies checks by plugin ID
    per host, so each check needs its own; the CRC of the check name gives the same ID in
    every pull."""
    import zlib
    return 1_000_000 + zlib.crc32((audit_file.strip().lower() + "|" + check_name.strip()).encode("utf-8")) % 99_000_000


def _item_record(el, host_name: str, hp: dict[str, str], repository_name: str) -> dict:
    pid = el.get("pluginID", "0")
    family = el.get("pluginFamily", "")
    sev = SEVERITY_NAMES.get(el.get("severity", "0"), "Info")
    ip = hp.get("host-ip") or (host_name if IP_RE.match(host_name) else "")
    fqdn = hp.get("host-fqdn") or ("" if IP_RE.match(host_name) else host_name)
    result = _text(el, CM + "compliance-result")
    compliance = bool(result) or family.lower() == "policy compliance"
    last = _date(hp.get("HOST_END", "")) or ""
    rec = {
        "pluginID": pid, "pluginName": el.get("pluginName", ""), "family": {"id": "", "name": family, "type": "compliance" if compliance else "active"},
        "severity": {"id": el.get("severity", "0"), "name": sev}, "ip": ip, "port": el.get("port", "0"), "protocol": el.get("protocol", "tcp"),
        "netbiosName": hp.get("netbios-name", ""), "dnsName": fqdn, "macAddress": hp.get("mac-address", "").split("\n")[0], "hostUUID": hp.get("host-uuid", ""), "agentID": hp.get("tenable_agent_uuid", "") or hp.get("agent-uuid", ""),
        "firstSeen": "", "lastSeen": last, "exploitAvailable": _text(el, "exploit_available"), "exploitEase": _text(el, "exploitability_ease"),
        "exploitFrameworks": ", ".join(n for n, tag in (("Metasploit", "exploit_framework_metasploit"), ("Core Impact", "exploit_framework_core"), ("Canvas", "exploit_framework_canvas")) if _text(el, tag).lower() == "true"),
        "synopsis": _text(el, "synopsis"), "description": _text(el, "description"), "solution": _text(el, "solution"), "seeAlso": _text(el, "see_also"), "riskFactor": _text(el, "risk_factor"), "stigSeverity": _text(el, "stig_severity"),
        "baseScore": _text(el, "cvss_base_score"), "temporalScore": _text(el, "cvss_temporal_score"), "cvssVector": _text(el, "cvss_vector"), "cvssV3BaseScore": _text(el, "cvss3_base_score"), "cvssV3TemporalScore": _text(el, "cvss3_temporal_score"), "cvssV3Vector": _text(el, "cvss3_vector"),
        "cpe": _texts(el, "cpe"), "vprScore": _text(el, "vpr_score"), "epssScore": _text(el, "epss_score"), "cve": _texts(el, "cve"), "bid": _texts(el, "bid"), "xref": _texts(el, "xref"),
        "pluginPubDate": _date(_text(el, "plugin_publication_date")), "pluginModDate": _date(_text(el, "plugin_modification_date")), "vulnPubDate": _date(_text(el, "vuln_publication_date")), "patchPubDate": _date(_text(el, "patch_publication_date")),
        "checkType": _text(el, "plugin_type"), "version": _text(el, "script_version"), "seolDate": _date(_text(el, "seol_date")), "pluginText": _text(el, "plugin_output"),
        "repository": {"id": repository_name, "name": repository_name}, "operatingSystem": hp.get("operating-system", ""),
    }
    if compliance:
        name = _text(el, CM + "compliance-check-name") or rec["pluginName"]
        audit = _text(el, CM + "compliance-audit-file")
        rec["nessusPluginID"] = pid
        rec["pluginID"] = str(compliance_plugin_id(name, audit))
        rec["pluginName"] = name
        rec["severity"] = {"id": {"FAILED": "3", "WARNING": "2", "ERROR": "2"}.get(result, "0"), "name": {"FAILED": "High", "WARNING": "Medium", "ERROR": "Medium"}.get(result, "Info")}
        parts = [f'"{name}" : [{result or "PASSED"}]', ""]
        info = _text(el, CM + "compliance-info")
        if info:
            parts += [f"Information: {info}", ""]
        parts += [f"Result: {result or 'PASSED'}", "", f"Actual Value: {_text(el, CM + 'compliance-actual-value')}", "", f"Policy Value: {_text(el, CM + 'compliance-policy-value')}", ""]
        sol = _text(el, CM + "compliance-solution")
        if sol:
            parts += [f"Solution: {sol}", ""]
        sa = _text(el, CM + "compliance-see-also")
        if sa:
            parts += [f"See Also: {sa}", ""]
        ref = _text(el, CM + "compliance-reference")
        if ref:
            parts += [f"Reference Information: {ref}"]
        rec["pluginText"] = "\n".join(parts).strip()
        rec["xref"] = f"auditFile #{'unix' if 'unix' in audit.lower() or 'linux' in audit.lower() else 'windows'}, nessusPlugin:{pid}"
        rec["solution"] = ""
    return rec


# ---- first seen carried forward -----------------------------------------------------------------
def previous_first_seen(store: ExportStore) -> dict[tuple, str]:
    """(plugin, ip, port, protocol) -> First Discovered of the most recent successful pull."""
    out: dict[tuple, str] = {}
    latest = store.latest()
    if not latest:
        return out
    for f in latest.get("files", []):
        try:
            with store.open_text(latest["id"], f["name"]) as fh:
                for row in csv_rows(fh):
                    key = (row.get("Plugin", ""), row.get("IP Address", ""), row.get("Port", "0"), (row.get("Protocol") or "").upper())
                    first = row.get("First Discovered") or row.get("Last Observed") or ""
                    if first and (key not in out or first < out[key]):
                        out[key] = first
        except (KeyError, OSError):
            continue
    return out


# ---- the pull ------------------------------------------------------------------------------------
def select_scans(listing: dict, cfg_scans: list, folder: str, max_age_days: int, now: float | None = None) -> list[dict]:
    now = now or time.time()
    folders = {str(f.get("id")): f.get("name") for f in listing.get("folders") or []}
    out = []
    for s in listing.get("scans") or []:
        if str(s.get("status", "")).lower() != "completed":
            continue
        if folder and folders.get(str(s.get("folder_id"))) != folder:
            continue
        if cfg_scans and not any(str(s.get("id")) == str(w) or str(s.get("name", "")).strip().lower() == str(w).strip().lower() for w in cfg_scans):
            continue
        mod = int(s.get("last_modification_date") or 0)
        if max_age_days and mod and (now - mod) > max_age_days * 86400:
            continue
        out.append(s)
    return out


def pull_nessus(cfg: Config, store: ExportStore, progress: PullProgress, client: NessusClient | None = None) -> dict:
    ncfg = cfg.nessus
    started = datetime.now(timezone.utc)
    pull_id, folder = store.new_pull_dir(started)
    progress.pull_id = pull_id
    date_label = started.strftime("%Y-%m-%d")
    manifest: dict = {"id": pull_id, "status": "running", "source": {"type": "nessus", "url": ncfg.url}, "started": started.isoformat(), "started_ts": started.timestamp(),
                      "trigger": progress.trigger, "connector_version": __version__, "files": [], "warnings": [], "counts": {}}
    own = client is None
    try:
        progress.set("connect", f"Connecting to Nessus at {ncfg.url}")
        if client is None:
            client = NessusClient(ncfg.url, ncfg.access_key, ncfg.secret_key, verify=ncfg.verify, timeout=ncfg.timeout)
        props = client.properties()
        manifest["source"]["version"] = props.get("server_version") or props.get("nessus_ui_version")
        manifest["source"]["product"] = props.get("nessus_type")
        listing = client.scans()
        chosen = select_scans(listing, ncfg.scans, ncfg.folder, ncfg.max_age_days)
        if not chosen:
            raise NessusError("no completed scan matches the configuration (nessus.scans / nessus.folder / nessus.max_age_days)")
        manifest["source"]["scans"] = [{"id": s.get("id"), "name": s.get("name"), "last_modification_date": s.get("last_modification_date")} for s in chosen]
        manifest["source"]["repositories"] = [{"id": s.get("id"), "name": s.get("name")} for s in chosen]
        progress.set("connect", f"Nessus {manifest['source']['version']}: exporting {len(chosen)} scans")
        carried = previous_first_seen(store)
        va = ExportWriter(folder / f"Nessus VA export {date_label}.csv", cfg.store.compress)
        cmp = ExportWriter(folder / f"Nessus Compliance export {date_label}.csv", cfg.store.compress)
        seen: set = set()
        dup = 0
        new_first = 0
        for i, s in enumerate(chosen, start=1):
            progress.set("export", f"Exporting scan {i}/{len(chosen)}: {s.get('name')}")
            blob = client.export_nessus(int(s["id"]))
            (folder / f"scan-{s['id']}.nessus").write_bytes(blob) if len(blob) < 50_000_000 else None
            n = 0
            for rec in parse_nessus(blob, str(s.get("name") or s.get("id"))):
                key = dedup_key(rec)
                if key in seen:
                    dup += 1
                    continue
                seen.add(key)
                k2 = (rec["pluginID"], rec["ip"], rec["port"] or "0", (rec["protocol"] or "").upper())
                rec["firstSeen"] = carried.get(k2) or rec["lastSeen"]
                if k2 not in carried:
                    new_first += 1
                row = sc_record_to_row(rec)
                (cmp if is_compliance(rec) else va).write(row)
                n += 1
                if n % 1000 == 0:
                    progress.set("export", f"Scan {s.get('name')}: {n:,} rows", va.rows + cmp.rows)
            progress.set("export", f"Scan {s.get('name')}: {n:,} rows", va.rows + cmp.rows)
        manifest["counts"] = {"duplicates_skipped": dup, "first_seen_new": new_first, "first_seen_carried": len(carried)}
        manifest["files"] = [va.close(), cmp.close()]
        manifest["files"][0]["kind"] = "va"
        manifest["files"][1]["kind"] = "compliance"
        manifest["scans"] = [{"id": s.get("id"), "name": s.get("name"), "status": s.get("status"), "finishTime": int(s.get("last_modification_date") or 0) or None, "repository": s.get("name")} for s in chosen]
        (folder / "scans.json").write_text(__import__("json").dumps({"results": listing.get("scans") or []}, indent=1), encoding="utf-8")
        finished = datetime.now(timezone.utc)
        manifest.update({"status": "ok", "finished": finished.isoformat(), "finished_ts": finished.timestamp(), "duration_s": round((finished - started).total_seconds(), 1)})
        manifest["summary"] = summarize(manifest)
        store.write_manifest(pull_id, manifest)
        progress.finished = time.time()
        progress.set("done", f"Pull {pull_id} complete: {manifest['summary']}")
        return manifest
    except Exception as e:   # noqa: BLE001
        finished = datetime.now(timezone.utc)
        manifest.update({"status": "failed", "error": str(e), "finished": finished.isoformat(), "finished_ts": finished.timestamp()})
        try:
            store.write_manifest(pull_id, manifest)
        except Exception:   # noqa: BLE001
            pass
        progress.error = str(e)
        progress.finished = time.time()
        progress.set("failed", f"Pull failed: {e}")
        raise
    finally:
        if own and client is not None:
            client.close()


def nessus_check(cfg: Config) -> dict:
    n = cfg.nessus
    with NessusClient(n.url, n.access_key, n.secret_key, verify=n.verify, timeout=60) as c:
        props = c.properties()
        listing = c.scans()
        chosen = select_scans(listing, n.scans, n.folder, n.max_age_days)
    return {"ok": True, "type": "nessus", "url": n.url, "version": props.get("server_version"), "product": props.get("nessus_type"),
            "scans": [{"id": s.get("id"), "name": s.get("name"), "status": s.get("status"), "last_modification_date": s.get("last_modification_date")} for s in listing.get("scans") or []],
            "selected": [s.get("name") for s in chosen], "checked": time.time()}
