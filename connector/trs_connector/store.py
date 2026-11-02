"""The export store: one folder per pull, named by date, with the export files, the risk rules,
the recent scans and a manifest.  Nothing else writes into it.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Iterable

from .export_schema import HEADERS

SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SAFE_FILE = re.compile(r"^[A-Za-z0-9 _.()-]{1,120}$")


class ExportWriter:
    """Streams rows into a CSV (optionally gzip-compressed), counting as it goes."""

    def __init__(self, path: Path, compress: bool):
        self.path = path.with_suffix(path.suffix + ".gz") if compress and not path.name.endswith(".gz") else path
        self.compress = compress
        self.rows = 0
        self.hosts: set[str] = set()
        self.severity: dict[str, int] = {}
        self._fh: IO[str] = gzip.open(self.path, "wt", encoding="utf-8", newline="") if compress else open(self.path, "w", encoding="utf-8", newline="")
        self._fh.write("﻿")   # BOM so that Excel opens the file as UTF-8; the Studio strips it
        self._w = csv.writer(self._fh, lineterminator="\r\n")
        self._w.writerow(HEADERS)

    def write(self, row: dict[str, str]) -> None:
        self._w.writerow([row.get(h, "") for h in HEADERS])
        self.rows += 1
        if row.get("IP Address"):
            self.hosts.add(row["IP Address"])
        sev = row.get("Severity") or "Info"
        self.severity[sev] = self.severity.get(sev, 0) + 1

    def close(self) -> dict:
        self._fh.close()
        size = self.path.stat().st_size
        return {"name": self.path.name, "display_name": self.path.name[:-3] if self.path.name.endswith(".gz") else self.path.name,
                "rows": self.rows, "hosts": len(self.hosts), "severity": self.severity, "bytes": size, "sha256": sha256_of(self.path), "compressed": self.compress}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ExportStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # ---- pulls ------------------------------------------------------------------------------
    def new_pull_dir(self, when: datetime | None = None) -> tuple[str, Path]:
        when = when or datetime.now(timezone.utc)
        base = when.strftime("%Y-%m-%d")
        with self._lock:
            pull_id = base
            if (self.root / pull_id).exists():
                pull_id = when.strftime("%Y-%m-%d_%H%M%S")
            d = self.root / pull_id
            d.mkdir(parents=True)
        return pull_id, d

    def pull_dir(self, pull_id: str) -> Path:
        if not SAFE_ID.match(pull_id or ""):
            raise KeyError(pull_id)
        d = self.root / pull_id
        if not d.is_dir():
            raise KeyError(pull_id)
        return d

    def write_manifest(self, pull_id: str, manifest: dict) -> None:
        d = self.pull_dir(pull_id)
        tmp = d / "manifest.json.tmp"
        tmp.write_text(json.dumps(manifest, indent=1, ensure_ascii=False), encoding="utf-8")
        tmp.replace(d / "manifest.json")

    def manifest(self, pull_id: str) -> dict | None:
        p = self.pull_dir(pull_id) / "manifest.json"
        if not p.exists():
            return None
        try:
            m = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None
        m.setdefault("id", pull_id)
        return m

    def list_pulls(self, include_failed: bool = False) -> list[dict]:
        out = []
        for d in sorted(self.root.iterdir(), reverse=True):
            if not d.is_dir() or not SAFE_ID.match(d.name):
                continue
            m = self.manifest(d.name)
            if not m:
                continue
            if m.get("status") != "ok" and not include_failed:
                continue
            out.append(m)
        return out

    def latest(self) -> dict | None:
        pulls = self.list_pulls()
        return pulls[0] if pulls else None

    def file_path(self, pull_id: str, name: str) -> Path:
        if not SAFE_FILE.match(name or "") or "/" in name or "\\" in name:
            raise KeyError(name)
        d = self.pull_dir(pull_id)
        for candidate in (d / name, d / (name + ".gz")):
            if candidate.is_file():
                return candidate
        raise KeyError(name)

    def open_text(self, pull_id: str, name: str) -> IO[str]:
        p = self.file_path(pull_id, name)
        if p.name.endswith(".gz"):
            return gzip.open(p, "rt", encoding="utf-8", newline="")
        return open(p, "r", encoding="utf-8", newline="")

    def read_json(self, pull_id: str, name: str) -> object:
        p = self.file_path(pull_id, name)
        return json.loads(p.read_text(encoding="utf-8"))

    def delete(self, pull_id: str) -> None:
        shutil.rmtree(self.pull_dir(pull_id))

    def cleanup(self, retention_days: int) -> list[str]:
        """Remove successful pulls older than the retention; failed pulls older than 7 days."""
        removed = []
        now = time.time()
        for m in self.list_pulls(include_failed=True):
            age_days = (now - m.get("finished_ts", m.get("started_ts", now))) / 86400
            limit = retention_days if m.get("status") == "ok" else 7
            if limit and age_days > limit:
                try:
                    self.delete(m["id"])
                    removed.append(m["id"])
                except OSError:
                    pass
        return removed

    def stats(self) -> dict:
        pulls = self.list_pulls(include_failed=True)
        total = 0
        for d in self.root.iterdir():
            if d.is_dir():
                total += sum(p.stat().st_size for p in d.rglob("*") if p.is_file())
        return {"pulls": len([p for p in pulls if p.get("status") == "ok"]), "failed": len([p for p in pulls if p.get("status") != "ok"]), "bytes": total, "dir": str(self.root)}

    # ---- shared state (settings.json and risk-register.json kept for the team) -------------------
    def state_path(self, name: str) -> Path:
        d = self.root / "_state"
        d.mkdir(exist_ok=True)
        return d / name

    def read_state(self, name: str) -> dict | None:
        p = self.state_path(name)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None

    def write_state(self, name: str, data: dict) -> None:
        p = self.state_path(name)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(p)
        # keep a few generations, the register is precious
        hist = self.root / "_state" / "history"
        hist.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        shutil.copyfile(p, hist / f"{p.stem}-{stamp}{p.suffix}")
        old = sorted(hist.glob(f"{p.stem}-*{p.suffix}"))
        for stale in old[:-20]:
            stale.unlink(missing_ok=True)


def csv_rows(fh: IO[str]) -> Iterable[dict[str, str]]:
    reader = csv.DictReader(fh)
    for row in reader:
        yield {k.lstrip("﻿"): v for k, v in row.items()}


def read_export(store: ExportStore, pull_id: str, name: str) -> list[dict[str, str]]:
    with store.open_text(pull_id, name) as fh:
        return list(csv_rows(fh))


def export_bytes(store: ExportStore, pull_id: str, name: str) -> bytes:
    with store.open_text(pull_id, name) as fh:
        return fh.read().encode("utf-8")


def rows_to_csv_bytes(rows: list[dict[str, str]]) -> bytes:
    buf = io.StringIO(newline="")
    buf.write("﻿")
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(HEADERS)
    for r in rows:
        w.writerow([r.get(h, "") for h in HEADERS])
    return buf.getvalue().encode("utf-8")
