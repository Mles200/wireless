"""A pull: everything the weekly report needs, taken from Security Center (or Nessus) and
written into one dated folder of the store as Studio-ready export files.

Security Center pull
  1. system version, current user, repositories
  2. vulnerability query: severities Critical..Low (config), every repository (or the configured
     ones), cumulative source, tool vulndetails -> "SC VA export <date>.csv"
  3. inventory query: severity Info restricted to the inventory plugins -> appended to the VA
     export, so hosts without findings stay listed as scanned
  4. compliance query: pluginType compliance, severities Info/Medium/High -> "SC Compliance
     export <date>.csv" (Info = passed checks, needed for the pass rate)
  Rows are routed by their nature (compliance plugin or not), not by the query that returned
  them, and duplicates (same plugin, host, port, protocol and repository) are written once.
  5. Accept Risk and Recast Risk rules -> risk-rules.json; recent scan results -> scans.json
  6. manifest.json with the counts, the filters, the source and the timings
"""
from __future__ import annotations

import logging
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .config import Config
from .export_schema import dedup_key, is_compliance, sc_record_to_row
from .sc_client import SCError, SecurityCenterClient, resolve_repositories, vuln_filters
from .store import ExportStore, ExportWriter

log = logging.getLogger(__name__)


class PullProgress:
    """Shared between the pull thread and the API: what the pull is doing right now."""

    def __init__(self, trigger: str = "manual", source: str = "sc"):
        self.id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.trigger = trigger
        self.source = source
        self.phase = "starting"
        self.message = "Starting"
        self.rows = 0
        self.total: int | None = None
        self.started = time.time()
        self.finished: float | None = None
        self.error: str | None = None
        self.pull_id: str | None = None
        self.log: list[str] = []
        self._lock = threading.Lock()

    def set(self, phase: str, message: str, rows: int | None = None, total: int | None = None) -> None:
        with self._lock:
            self.phase = phase
            self.message = message
            if rows is not None:
                self.rows = rows
            if total is not None:
                self.total = total
            stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.log.append(f"{stamp} {message}")
            if len(self.log) > 200:
                del self.log[:-200]
        log.info("pull %s: %s", self.id, message)

    def to_dict(self) -> dict:
        with self._lock:
            return {"id": self.id, "trigger": self.trigger, "source": self.source, "phase": self.phase, "message": self.message, "rows": self.rows, "total": self.total,
                    "started": self.started, "finished": self.finished, "running": self.finished is None, "error": self.error, "pull_id": self.pull_id,
                    "elapsed": round((self.finished or time.time()) - self.started, 1), "log": list(self.log[-40:])}


def _route_rows(records, va: ExportWriter, cmp: ExportWriter, seen: set, counters: dict) -> None:
    for rec in records:
        key = dedup_key(rec)
        if key in seen:
            counters["duplicates"] += 1
            continue
        seen.add(key)
        row = sc_record_to_row(rec)
        (cmp if is_compliance(rec) else va).write(row)


def pull_security_center(cfg: Config, store: ExportStore, progress: PullProgress, client: SecurityCenterClient | None = None) -> dict:
    """Run one Security Center pull.  Returns the manifest; raises on failure (the manifest of the
    failed pull is still written with status "failed")."""
    sc = cfg.sc
    started = datetime.now(timezone.utc)
    pull_id, folder = store.new_pull_dir(started)
    progress.pull_id = pull_id
    date_label = started.strftime("%Y-%m-%d")
    manifest: dict = {"id": pull_id, "status": "running", "source": {"type": "sc", "url": sc.url}, "started": started.isoformat(), "started_ts": started.timestamp(),
                      "trigger": progress.trigger, "connector_version": __version__, "files": [], "warnings": [], "counts": {}}
    own_client = client is None
    try:
        progress.set("connect", f"Connecting to Security Center at {sc.url}")
        if client is None:
            client = SecurityCenterClient(sc.url, sc.access_key, sc.secret_key, verify=sc.verify, timeout=sc.timeout)
        system = client.system()
        manifest["source"]["version"] = system.get("version")
        manifest["source"]["build"] = system.get("buildID")
        try:
            user = client.current_user()
            manifest["source"]["user"] = user.get("username")
            manifest["source"]["organization"] = (user.get("organization") or {}).get("name") if isinstance(user.get("organization"), dict) else user.get("organization")
        except SCError as e:
            manifest["warnings"].append(f"currentUser: {e}")
        repos_all = client.repositories()
        repos = resolve_repositories(sc.repositories, repos_all)
        manifest["source"]["repositories"] = [{"id": r.get("id"), "name": r.get("name"), "type": r.get("type"), "dataFormat": r.get("dataFormat")} for r in (repos or repos_all)]
        progress.set("connect", f"Security Center {system.get('version', '?')}: {len(repos_all)} repositories, exporting {'all' if not repos else len(repos)}")

        va = ExportWriter(folder / f"SC VA export {date_label}.csv", cfg.store.compress)
        cmp = ExportWriter(folder / f"SC Compliance export {date_label}.csv", cfg.store.compress)
        seen: set = set()
        counters = {"duplicates": 0}
        queries = []
        # 1. vulnerabilities
        f_va = vuln_filters(sc.severities, repos, None, None, sc.extra_filters, sc.exclude_was)
        queries.append(("vulnerabilities", {"filters": f_va}, sc.page_size))
        # 2. inventory (Info rows of the inventory plugins)
        if sc.include_inventory and sc.inventory_plugins:
            f_inv = vuln_filters("0", repos, None, [int(p) for p in sc.inventory_plugins], None, sc.exclude_was)
            queries.append(("inventory", {"filters": f_inv}, sc.page_size))
        # 3. compliance
        f_cmp = vuln_filters(sc.compliance_severities, repos, "compliance", None, None, sc.exclude_was)
        queries.append(("compliance", {"filters": f_cmp}, sc.compliance_page_size))
        manifest["queries"] = [{"name": n, "filters": q["filters"], "page_size": ps} for n, q, ps in queries]

        for name, query, page_size in queries:
            progress.set(name, f"Fetching {name} (page size {page_size})", 0, None)

            def on_page(fetched: int, total: int | None, _name=name) -> None:
                progress.set(_name, f"Fetching {_name}: {fetched:,}{' of ' + format(total, ',') if total else ''} rows", fetched, total)
            t0 = time.time()
            before = (va.rows, cmp.rows)
            _route_rows(client.iter_analysis(query, page_size, sc.sort_field, on_page), va, cmp, seen, counters)
            manifest["counts"][name] = {"va_rows": va.rows - before[0], "compliance_rows": cmp.rows - before[1], "seconds": round(time.time() - t0, 1)}
            progress.set(name, f"{name}: {va.rows - before[0] + cmp.rows - before[1]:,} rows in {time.time() - t0:.0f} s")
        manifest["counts"]["duplicates_skipped"] = counters["duplicates"]
        manifest["files"] = [va.close(), cmp.close()]
        manifest["files"][0]["kind"] = "va"
        manifest["files"][1]["kind"] = "compliance"

        if sc.risk_rules:
            progress.set("rules", "Fetching Accept Risk and Recast Risk rules")
            rules = {"accept": [], "recast": [], "fetched": datetime.now(timezone.utc).isoformat()}
            try:
                rules["accept"] = client.accept_risk_rules()
                rules["recast"] = client.recast_risk_rules()
            except SCError as e:
                manifest["warnings"].append(f"risk rules: {e}")
            (folder / "risk-rules.json").write_text(_json(rules), encoding="utf-8")
            manifest["risk_rules"] = {"accept": len(rules["accept"]), "recast": len(rules["recast"])}
        if sc.scan_results:
            progress.set("scans", "Fetching recent scan results")
            try:
                scans = client.scan_results(sc.scan_results_days)
            except SCError as e:
                scans = []
                manifest["warnings"].append(f"scan results: {e}")
            (folder / "scans.json").write_text(_json({"days": sc.scan_results_days, "results": scans}), encoding="utf-8")
            manifest["scans"] = _scan_summary(scans)

        finished = datetime.now(timezone.utc)
        manifest.update({"status": "ok", "finished": finished.isoformat(), "finished_ts": finished.timestamp(), "duration_s": round((finished - started).total_seconds(), 1)})
        manifest["summary"] = summarize(manifest)
        store.write_manifest(pull_id, manifest)
        if cfg.store.retention_days:
            removed = store.cleanup(cfg.store.retention_days)
            if removed:
                progress.set("cleanup", f"Removed {len(removed)} pulls older than {cfg.store.retention_days} days")
        progress.finished = time.time()
        progress.set("done", f"Pull {pull_id} complete: {manifest['summary']}")
        return manifest
    except Exception as e:   # noqa: BLE001 - the failure is recorded in the manifest and re-raised
        finished = datetime.now(timezone.utc)
        manifest.update({"status": "failed", "error": str(e), "traceback": traceback.format_exc()[-4000:], "finished": finished.isoformat(), "finished_ts": finished.timestamp()})
        try:
            store.write_manifest(pull_id, manifest)
        except Exception:   # noqa: BLE001
            pass
        progress.error = str(e)
        progress.finished = time.time()
        progress.set("failed", f"Pull failed: {e}")
        raise
    finally:
        if own_client and client is not None:
            client.close()


def summarize(manifest: dict) -> str:
    files = manifest.get("files") or []
    parts = []
    for f in files:
        sev = f.get("severity") or {}
        if f.get("kind") == "va":
            parts.append(f"{f['rows']:,} vulnerability rows on {f['hosts']:,} hosts ({sev.get('Critical', 0):,} Critical, {sev.get('High', 0):,} High, {sev.get('Medium', 0):,} Medium, {sev.get('Low', 0):,} Low, {sev.get('Info', 0):,} Info)")
        else:
            parts.append(f"{f['rows']:,} compliance rows on {f['hosts']:,} hosts")
    dup = (manifest.get("counts") or {}).get("duplicates_skipped")
    if dup:
        parts.append(f"{dup:,} duplicate rows skipped")
    return "; ".join(parts)


def _scan_summary(scans: list[dict]) -> list[dict]:
    out = []
    for s in scans or []:
        try:
            out.append({"id": s.get("id"), "name": s.get("name"), "status": s.get("status"), "finishTime": int(s.get("finishTime") or 0) or None, "startTime": int(s.get("startTime") or 0) or None,
                        "scannedIPs": s.get("scannedIPs"), "totalIPs": s.get("totalIPs"), "importStatus": s.get("importStatus"),
                        "repository": (s.get("repository") or {}).get("name") if isinstance(s.get("repository"), dict) else s.get("repository")})
        except (TypeError, ValueError):
            continue
    out.sort(key=lambda x: x.get("finishTime") or 0, reverse=True)
    return out[:50]


def _json(obj) -> str:
    import json
    return json.dumps(obj, indent=1, ensure_ascii=False)


class PullRunner:
    """Runs one pull at a time in a background thread; keeps the last few progress records."""

    def __init__(self, cfg: Config, store: ExportStore):
        self.cfg = cfg
        self.store = store
        self.current: PullProgress | None = None
        self.history: list[PullProgress] = []
        self._lock = threading.Lock()
        self.on_finished: list[Callable[[PullProgress], None]] = []

    def running(self) -> bool:
        return self.current is not None and self.current.finished is None

    def start(self, trigger: str = "manual", source: str | None = None) -> PullProgress:
        with self._lock:
            if self.running():
                raise RuntimeError("a pull is already running")
            source = source or ("sc" if self.cfg.sc.enabled else "nessus")
            progress = PullProgress(trigger, source)
            self.current = progress
            self.history.append(progress)
            del self.history[:-10]
        t = threading.Thread(target=self._run, args=(progress,), name=f"pull-{progress.id}", daemon=True)
        t.start()
        return progress

    def _run(self, progress: PullProgress) -> None:
        try:
            if progress.source == "nessus":
                from .nessus_source import pull_nessus
                pull_nessus(self.cfg, self.store, progress)
            else:
                pull_security_center(self.cfg, self.store, progress)
        except Exception:   # noqa: BLE001 - recorded in progress
            log.exception("pull %s failed", progress.id)
        finally:
            for cb in self.on_finished:
                try:
                    cb(progress)
                except Exception:   # noqa: BLE001
                    log.exception("on_finished callback failed")

    def status(self) -> dict | None:
        return self.current.to_dict() if self.current else None

    def find(self, job_id: str) -> PullProgress | None:
        return next((p for p in self.history if p.id == job_id), None)


def run_pull_blocking(cfg: Config, store: ExportStore, trigger: str = "cli", source: str | None = None) -> dict:
    source = source or ("sc" if cfg.sc.enabled else "nessus")
    progress = PullProgress(trigger, source)
    if source == "nessus":
        from .nessus_source import pull_nessus
        return pull_nessus(cfg, store, progress)
    return pull_security_center(cfg, store, progress)


def ensure_store(cfg: Config) -> ExportStore:
    return ExportStore(Path(cfg.store.dir))
