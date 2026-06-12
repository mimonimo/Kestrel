"""APScheduler wiring. Registers a job per parser with staggered intervals
so that rate-limited sources don't collide on startup.
"""
from __future__ import annotations

import asyncio

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import AppSettings
from app.services.aggregate_snapshots import refresh_snapshots
from app.services.ingestion import run_parser
from app.services.parsers import ExploitDbParser, GithubAdvisoryParser, NvdParser
from app.services.parsers.mitre import MitreParser
from app.services.priority_signals import refresh_epss, refresh_kev
from app.services.search_reconcile import reconcile_search_index

log = get_logger(__name__)


async def _resolve_external_keys() -> tuple[str | None, str | None]:
    """Pull NVD/GitHub keys from app_settings as a fallback for the env vars.

    PR 10-AJ — without this the scheduler ran token-less even when the user
    had set keys via the dashboard, because /admin/refresh used to keep
    them in-request only.
    """
    settings = get_settings()
    nvd = settings.nvd_api_key or None
    gh = settings.github_token or None
    if nvd and gh:
        return nvd, gh
    try:
        async with SessionLocal() as session:
            row = await session.scalar(select(AppSettings).where(AppSettings.id == 1))
            if row is not None:
                if not nvd:
                    nvd = row.nvd_api_key or None
                if not gh:
                    gh = row.github_token or None
    except Exception:
        log.exception("scheduler.app_settings_load_failed")
    return nvd, gh


def build_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler = AsyncIOScheduler(timezone="UTC")

    schedule = [
        (NvdParser, settings.nvd_interval_seconds, 30),
        (GithubAdvisoryParser, settings.github_advisory_interval_seconds, 90),
        (ExploitDbParser, settings.exploit_db_interval_seconds, 150),
        # MITRE delta — only walks files modified in git in the last
        # ``since_days`` so each tick is fast even though the repo is
        # ~5GB. Initial backfill is done out-of-band via /admin/mitre-backfill.
        (MitreParser, settings.mitre_interval_seconds, 210),
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

    # Priority signals — KEV refreshes hourly (catalog rarely changes
    # but is tiny, so cheap to poll), EPSS refreshes once a day (FIRST
    # publishes daily and the file is ~5MB compressed).
    scheduler.add_job(
        _safe_refresh, args=[refresh_kev, "kev"],
        trigger=IntervalTrigger(hours=1),
        id="priority-kev", max_instances=1, coalesce=True, misfire_grace_time=600,
    )
    scheduler.add_job(
        _safe_refresh, args=[refresh_kev, "kev"],
        id="priority-kev-boot",
        next_run_time=_now_plus(60), max_instances=1,
    )
    scheduler.add_job(
        _safe_refresh, args=[refresh_epss, "epss"],
        trigger=IntervalTrigger(hours=24),
        id="priority-epss", max_instances=1, coalesce=True, misfire_grace_time=3600,
    )
    # 부팅 직후가 아니라 워밍업이 끝난 뒤(+10분) 1회 — EPSS 갱신은 무거운
    # 배치라, 배포 직후 다른 부팅 작업과 겹치면 메모리 경합으로 실패하기 쉽다.
    scheduler.add_job(
        _safe_refresh, args=[refresh_epss, "epss"],
        id="priority-epss-boot",
        next_run_time=_now_plus(600), max_instances=1,
    )

    # 집계 스냅샷 — 무거운 facets/dashboard 집계를 10분마다 미리 계산해 Redis 에
    # 저장(perf-A2). API 는 스냅샷을 즉시 반환 → 매 요청 수십초 집계 제거.
    scheduler.add_job(
        _safe_refresh, args=[refresh_snapshots, "snapshots"],
        trigger=IntervalTrigger(minutes=10),
        id="aggregate-snapshots", max_instances=1, coalesce=True, misfire_grace_time=300,
    )
    # 부팅 직후 1회 — 배포 후 사용자가 곧바로 캐시된 대시보드를 받도록.
    scheduler.add_job(
        _safe_refresh, args=[refresh_snapshots, "snapshots"],
        id="aggregate-snapshots-boot",
        next_run_time=_now_plus(45), max_instances=1,
    )

    # 검색 색인 정합성 점검 — PG vs Meili 카운트 비교, 드리프트 시 자동 재색인.
    # 평상시엔 카운트 조회만(가벼움). 6시간마다 + 부팅 후 한 번.
    scheduler.add_job(
        _safe_refresh, args=[reconcile_search_index, "search-reconcile"],
        trigger=IntervalTrigger(hours=6),
        id="search-reconcile", max_instances=1, coalesce=True, misfire_grace_time=600,
    )
    scheduler.add_job(
        _safe_refresh, args=[reconcile_search_index, "search-reconcile"],
        id="search-reconcile-boot",
        next_run_time=_now_plus(300), max_instances=1,
    )

    return scheduler


async def _safe_refresh(fn, label: str) -> None:
    try:
        await fn()
    except Exception:
        log.exception("priority_signals.refresh_failed", which=label)


async def _run(parser_cls):
    nvd, gh = await _resolve_external_keys()
    if parser_cls is NvdParser:
        parser = parser_cls(api_key_override=nvd)
    elif parser_cls is GithubAdvisoryParser:
        parser = parser_cls(token_override=gh)
    else:
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
