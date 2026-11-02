"""The weekly pull: an asyncio task that waits for the configured weekday and time (in the
configured time zone) and starts a pull; a failed scheduled pull is retried after
``retry_minutes``.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .config import Config
from .exporter import PullRunner

log = logging.getLogger(__name__)
WEEKDAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


class Scheduler:
    def __init__(self, cfg: Config, runner: PullRunner):
        self.cfg = cfg
        self.runner = runner
        self.task: asyncio.Task | None = None
        self.last_started: float | None = None
        self.last_result: str | None = None
        self.retry_at: float | None = None
        runner.on_finished.append(self._finished)

    # ---- schedule arithmetic -----------------------------------------------------------------
    def tz(self) -> ZoneInfo:
        try:
            return ZoneInfo(self.cfg.schedule.timezone or "UTC")
        except Exception:   # noqa: BLE001 - unknown zone name
            log.warning("unknown timezone %r, using UTC", self.cfg.schedule.timezone)
            return ZoneInfo("UTC")

    def next_run(self, now: datetime | None = None) -> datetime | None:
        s = self.cfg.schedule
        if not s.enabled:
            return None
        tz = self.tz()
        now = (now or datetime.now(tz)).astimezone(tz)
        try:
            hh, mm = [int(x) for x in str(s.time).split(":")[:2]]
        except ValueError:
            hh, mm = 6, 0
        wd = str(s.weekday or "daily").strip().lower()[:3]
        candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        for i in range(0, 8):
            c = candidate + timedelta(days=i)
            if wd != "dai" and wd in WEEKDAYS and c.weekday() != WEEKDAYS[wd]:
                continue
            if c > now:
                return c
        return None

    def describe(self) -> dict:
        nxt = self.next_run()
        return {"enabled": self.cfg.schedule.enabled, "weekday": self.cfg.schedule.weekday, "time": self.cfg.schedule.time, "timezone": self.cfg.schedule.timezone,
                "next_run": nxt.isoformat() if nxt else None, "next_run_ts": nxt.timestamp() if nxt else None,
                "retry_at": self.retry_at, "last_started": self.last_started, "last_result": self.last_result}

    # ---- the loop ---------------------------------------------------------------------------
    def start(self) -> None:
        if self.cfg.schedule.enabled and self.task is None:
            self.task = asyncio.get_event_loop().create_task(self._loop(), name="trs-scheduler")

    def stop(self) -> None:
        if self.task:
            self.task.cancel()
            self.task = None

    async def _loop(self) -> None:
        log.info("scheduler: next pull %s", (self.next_run() or "never"))
        while True:
            try:
                nxt = self.next_run()
                due_ts = None
                if nxt:
                    due_ts = nxt.timestamp()
                if self.retry_at and (due_ts is None or self.retry_at < due_ts):
                    due_ts = self.retry_at
                if due_ts is None:
                    await asyncio.sleep(300)
                    continue
                delay = due_ts - time.time()
                if delay > 0:
                    await asyncio.sleep(min(delay, 60))
                    continue
                self.retry_at = None
                if self.runner.running():
                    await asyncio.sleep(60)
                    continue
                self.last_started = time.time()
                self.last_result = "running"
                self.runner.start("schedule")
                await asyncio.sleep(90)   # past the minute, so the same slot is not started twice
            except asyncio.CancelledError:
                raise
            except Exception:   # noqa: BLE001
                log.exception("scheduler loop error")
                await asyncio.sleep(60)

    def _finished(self, progress) -> None:
        if progress.trigger != "schedule":
            return
        if progress.error:
            self.last_result = f"failed: {progress.error}"
            if self.cfg.schedule.retry_minutes:
                self.retry_at = time.time() + self.cfg.schedule.retry_minutes * 60
                log.warning("scheduled pull failed, retrying in %d minutes", self.cfg.schedule.retry_minutes)
        else:
            self.last_result = f"ok: {progress.pull_id}"
            self.retry_at = None
