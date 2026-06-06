"""Liveness + status endpoints.

`/health` is intentionally small: returns 200 when the process is up so
container orchestrators (Docker healthcheck, k8s) can wire to it without
masking real outages with downstream-dependency checks.

`/status` does the deep check (DB/Redis/Meili + ingestion + missing keys)
that the frontend banner consumes. Splitting this avoids healthcheck
flapping when, say, Meilisearch is restarting — the API itself is fine
and the search path falls back to Postgres tsvector.

`/version` reports the running build (git commit SHA, build time,
alembic revision) so the operator can confirm an `update.sh` run
actually rolled new code into the container.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redis_client import get_redis
from app.models import AppSettings, IngestionLog, Source
from app.services.search_service import meili_healthy

router = APIRouter(tags=["health"])


class _CamelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)


class IngestionSnapshot(_CamelOut):
    source: Source
    finished_at: datetime | None
    status: str
    items_processed: int = 0
    error_message: str | None = None


class StatusReport(_CamelOut):
    api: bool = True
    db: bool
    redis: bool
    meili: bool
    nvd_key_present: bool
    github_token_present: bool
    ingestions: list[IngestionSnapshot]
    server_time: datetime


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/status", response_model=StatusReport, response_model_by_alias=True)
async def status(db: AsyncSession = Depends(get_db)) -> StatusReport:
    settings = get_settings()

    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    redis_ok = False
    try:
        redis = await get_redis()
        try:
            redis_ok = bool(await redis.ping())
        except Exception:
            # 부하 순간의 단발 타임아웃으로 redis=false 가 깜박이지 않게 1회 재시도.
            # (배포/수집 중 박스 포화 시 활동센터 오탐 방지. 지속 장애는 그대로 잡힘.)
            await asyncio.sleep(0.3)
            redis_ok = bool(await redis.ping())
    except Exception:
        redis_ok = False

    meili_ok = meili_healthy()

    snapshots: list[IngestionSnapshot] = []
    # Persisted keys: PR 10-AJ stores user-supplied NVD/GitHub keys in
    # ``app_settings`` so the scheduler keeps using them across restarts.
    # The status flag must reflect EITHER source so the dashboard banner
    # stops nagging "키 미설정" after the user saves a key via the UI.
    nvd_present = bool(settings.nvd_api_key)
    gh_present = bool(settings.github_token)
    if db_ok:
        for source in Source:
            stmt = (
                select(IngestionLog)
                .where(IngestionLog.source == source)
                .order_by(desc(IngestionLog.started_at))
                .limit(1)
            )
            row = (await db.execute(stmt)).scalar_one_or_none()
            if row is not None:
                snapshots.append(IngestionSnapshot.model_validate(row))
        if not (nvd_present and gh_present):
            saved = await db.scalar(select(AppSettings).where(AppSettings.id == 1))
            if saved is not None:
                nvd_present = nvd_present or bool(saved.nvd_api_key)
                gh_present = gh_present or bool(saved.github_token)

    return StatusReport(
        db=db_ok,
        redis=redis_ok,
        meili=meili_ok,
        nvd_key_present=nvd_present,
        github_token_present=gh_present,
        ingestions=snapshots,
        server_time=datetime.now(timezone.utc),
    )


class VersionReport(_CamelOut):
    git_commit: str
    git_commit_short: str
    build_time: str
    alembic_revision: str | None
    started_at: datetime


# Captured once at import time so /version reflects the *running* process
# (uvicorn worker uptime), not when the latest request arrived.
_PROCESS_STARTED_AT = datetime.now(timezone.utc)


@router.get(
    "/version", response_model=VersionReport, response_model_by_alias=True
)
async def version(db: AsyncSession = Depends(get_db)) -> VersionReport:
    """Identify the running build.

    `git_commit` / `build_time` come from build-args baked into the
    backend image during `docker compose build` (default = "unknown"
    when developers `docker compose up` against a partially-staged
    tree). `alembic_revision` is read live from the DB so a user who
    forgot to restart after `git pull` can see "DB is at 0014 but image
    expects 0015" mismatches.
    """
    git_commit = os.environ.get("KESTREL_GIT_COMMIT", "unknown")
    build_time = os.environ.get("KESTREL_BUILD_TIME", "unknown")

    rev: str | None = None
    try:
        rev = (
            await db.execute(text("SELECT version_num FROM alembic_version"))
        ).scalar_one_or_none()
    except Exception:
        rev = None

    return VersionReport(
        git_commit=git_commit,
        git_commit_short=git_commit[:7] if git_commit != "unknown" else "unknown",
        build_time=build_time,
        alembic_revision=rev,
        started_at=_PROCESS_STARTED_AT,
    )
