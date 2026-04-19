"""Liveness + status endpoints.

`/health` is intentionally small: returns 200 when the process is up so
container orchestrators (Docker healthcheck, k8s) can wire to it without
masking real outages with downstream-dependency checks.

`/status` does the deep check (DB/Redis/Meili + ingestion + missing keys)
that the frontend banner consumes. Splitting this avoids healthcheck
flapping when, say, Meilisearch is restarting — the API itself is fine
and the search path falls back to Postgres tsvector.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redis_client import get_redis
from app.models import IngestionLog, Source
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
        redis_ok = bool(await redis.ping())
    except Exception:
        redis_ok = False

    meili_ok = meili_healthy()

    snapshots: list[IngestionSnapshot] = []
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

    return StatusReport(
        db=db_ok,
        redis=redis_ok,
        meili=meili_ok,
        nvd_key_present=bool(settings.nvd_api_key),
        github_token_present=bool(settings.github_token),
        ingestions=snapshots,
        server_time=datetime.now(timezone.utc),
    )
