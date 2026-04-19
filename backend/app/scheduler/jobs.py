"""APScheduler wiring. Registers a job per parser with staggered intervals
so that rate-limited sources don't collide on startup.
"""
from __future__ import annotations

import asyncio

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.ingestion import run_parser
from app.services.parsers import ExploitDbParser, GithubAdvisoryParser, NvdParser

log = get_logger(__name__)


def build_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler = AsyncIOScheduler(timezone="UTC")

    schedule = [
        (NvdParser, settings.nvd_interval_seconds, 30),
        (GithubAdvisoryParser, settings.github_advisory_interval_seconds, 90),
        (ExploitDbParser, settings.exploit_db_interval_seconds, 150),
    ]

    for parser_cls, interval, first_delay in schedule:
        scheduler.add_job(
            _run,
            trigger=IntervalTrigger(seconds=interval),
            args=[parser_cls],
            id=f"ingest-{parser_cls.source.value}",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=120,
        )
        # Kick off first run shortly after startup
        scheduler.add_job(_run, args=[parser_cls], id=f"ingest-{parser_cls.source.value}-boot",
                          next_run_time=_now_plus(first_delay), max_instances=1)

    return scheduler


async def _run(parser_cls):
    parser = parser_cls()
    try:
        await run_parser(parser)
    except Exception:
        log.exception("scheduler.job_failed", parser=parser_cls.__name__)


def _now_plus(seconds: float):
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


async def run_once_all() -> None:
    """Manual trigger for all parsers. Useful for ops endpoints / tests."""
    await asyncio.gather(
        _run(NvdParser), _run(GithubAdvisoryParser), _run(ExploitDbParser),
        return_exceptions=True,
    )
