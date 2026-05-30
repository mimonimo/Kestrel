"""Resource management — DB / Redis / Meili usage and admin actions.

Backs the settings-page "내부 자원" surface so an operator can see at a
glance how much each subsystem is consuming and run a few targeted
maintenance actions (Redis FLUSHDB, Meili index drop, ANALYZE) without
shelling into containers. Every action is *destructive in scope but
recoverable* — Redis cache rebuilds itself on the next ingestion, Meili
can be reindexed from Postgres, ANALYZE only updates planner stats.
"""
from __future__ import annotations

import asyncio
from typing import Any

import meilisearch
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import require_admin
from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.services.search_service import _client as meili_client

# 모든 자원 점검/조작 라우트는 admin only (DB ANALYZE, Redis FLUSH, Meili reset 등).
router = APIRouter(prefix="/resources", tags=["resources"], dependencies=[Depends(require_admin)])
log = get_logger(__name__)


class _CamelOut(BaseModel):
    model_config = ConfigDict(
        from_attributes=True, alias_generator=to_camel, populate_by_name=True
    )


class TableSize(_CamelOut):
    name: str
    rows: int
    total_bytes: int


class DbResource(_CamelOut):
    healthy: bool
    pg_version: str | None
    db_size_bytes: int | None
    table_sizes: list[TableSize]
    error: str | None = None


class RedisResource(_CamelOut):
    healthy: bool
    used_memory_bytes: int | None
    key_count: int | None
    redis_version: str | None
    error: str | None = None


class MeiliResource(_CamelOut):
    healthy: bool
    index_uid: str
    document_count: int | None
    raw_size_bytes: int | None
    index_count: int | None
    meili_version: str | None
    error: str | None = None


class ResourceReport(_CamelOut):
    db: DbResource
    redis: RedisResource
    meili: MeiliResource


class ActionResponse(_CamelOut):
    ok: bool
    detail: str
    payload: dict[str, Any] | None = None


# Tables we care about for capacity reporting. Sorted roughly by
# expected size — vulnerabilities + affected_products dwarf everything
# else, then references, mappings, sessions, logs.
_TRACKED_TABLES = (
    "vulnerabilities",
    "affected_products",
    "references",
    "vulnerability_types",
    "vulnerability_type_map",
    "cve_lab_mappings",
    "cve_lab_feedback",
    "sandbox_sessions",
    "ingestion_logs",
    "ai_credentials",
    "app_settings",
    "bookmarks",
    "tickets",
    "comments",
    "votes",
    "posts",
    "tags",
    "users",
)


async def _db_resource(db: AsyncSession) -> DbResource:
    try:
        pg_version = (
            await db.execute(text("SHOW server_version"))
        ).scalar_one_or_none()
        db_size = (
            await db.execute(
                text("SELECT pg_database_size(current_database())")
            )
        ).scalar_one_or_none()
        # Build the IN list as bound params so we don't risk SQL injection
        # if _TRACKED_TABLES is ever sourced from config. ``schema=public``
        # since alembic migrations always use the default schema.
        rows = (
            await db.execute(
                text(
                    """
                    SELECT relname,
                           reltuples::bigint AS row_estimate,
                           pg_total_relation_size(c.oid) AS bytes
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public'
                      AND c.relkind = 'r'
                      AND c.relname = ANY(:tables)
                    ORDER BY bytes DESC
                    """
                ),
                {"tables": list(_TRACKED_TABLES)},
            )
        ).all()
        sizes = [
            TableSize(name=r[0], rows=int(r[1] or 0), total_bytes=int(r[2] or 0))
            for r in rows
        ]
        return DbResource(
            healthy=True,
            pg_version=pg_version,
            db_size_bytes=int(db_size) if db_size is not None else None,
            table_sizes=sizes,
        )
    except Exception as e:
        log.warning("resources.db_failed", error=str(e))
        return DbResource(
            healthy=False,
            pg_version=None,
            db_size_bytes=None,
            table_sizes=[],
            error=str(e),
        )


async def _redis_resource() -> RedisResource:
    try:
        redis = await get_redis()
        info = await redis.info()  # type: ignore[no-untyped-call]
        used = info.get("used_memory")
        version = info.get("redis_version")
        keys = await redis.dbsize()
        return RedisResource(
            healthy=True,
            used_memory_bytes=int(used) if used is not None else None,
            key_count=int(keys) if keys is not None else None,
            redis_version=str(version) if version else None,
        )
    except Exception as e:
        log.warning("resources.redis_failed", error=str(e))
        return RedisResource(
            healthy=False,
            used_memory_bytes=None,
            key_count=None,
            redis_version=None,
            error=str(e),
        )


def _meili_resource_blocking() -> MeiliResource:
    s = get_settings()
    try:
        client = meili_client()
        index = client.index(s.meili_index)
        stats = index.get_stats()
        # `stats` is the SDK's IndexStats wrapper; unwrap defensively
        # because v1.x returns either an object with attrs or a dict
        # depending on patch version.
        doc_count = getattr(stats, "number_of_documents", None) or (
            stats.get("numberOfDocuments") if isinstance(stats, dict) else None
        )
        raw_size = getattr(stats, "raw_document_db_size", None) or (
            stats.get("rawDocumentDbSize") if isinstance(stats, dict) else None
        )
        all_stats = client.get_all_stats()
        all_size = getattr(all_stats, "database_size", None) or (
            all_stats.get("databaseSize") if isinstance(all_stats, dict) else None
        )
        index_count = (
            len(getattr(all_stats, "indexes", {}) or {})
            if not isinstance(all_stats, dict)
            else len((all_stats or {}).get("indexes", {}) or {})
        )
        version_obj = client.get_version()
        version = (
            getattr(version_obj, "pkg_version", None)
            or (version_obj.get("pkgVersion") if isinstance(version_obj, dict) else None)
        )
        return MeiliResource(
            healthy=True,
            index_uid=s.meili_index,
            document_count=int(doc_count) if doc_count is not None else None,
            raw_size_bytes=int(raw_size) if raw_size is not None else (int(all_size) if all_size is not None else None),
            index_count=int(index_count) if index_count else None,
            meili_version=str(version) if version else None,
        )
    except Exception as e:
        log.warning("resources.meili_failed", error=str(e))
        return MeiliResource(
            healthy=False,
            index_uid=s.meili_index,
            document_count=None,
            raw_size_bytes=None,
            index_count=None,
            meili_version=None,
            error=str(e),
        )


async def _meili_resource() -> MeiliResource:
    # The meilisearch SDK is sync; offload to a thread so we don't block
    # the event loop while the HTTP roundtrip happens.
    return await asyncio.to_thread(_meili_resource_blocking)


@router.get(
    "", response_model=ResourceReport, response_model_by_alias=True
)
async def report(db: AsyncSession = Depends(get_db)) -> ResourceReport:
    db_res = await _db_resource(db)
    redis_res = await _redis_resource()
    meili_res = await _meili_resource()
    return ResourceReport(db=db_res, redis=redis_res, meili=meili_res)


@router.post(
    "/redis/flush",
    response_model=ActionResponse,
    response_model_by_alias=True,
)
async def redis_flush() -> ActionResponse:
    """Drop everything in the configured Redis DB.

    Intended use: clear stuck ingestion cursors / cached HTTP responses
    when a parser bug sticks bad data in. Recoverable — caches rebuild
    on the next ingestion run.
    """
    try:
        redis = await get_redis()
        before = await redis.dbsize()
        await redis.flushdb()
        return ActionResponse(
            ok=True,
            detail=f"Redis 캐시를 비웠습니다 (삭제된 키 {before}개).",
            payload={"flushed": int(before)},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Redis 비우기 실패: {e}")


@router.post(
    "/db/analyze",
    response_model=ActionResponse,
    response_model_by_alias=True,
)
async def db_analyze(db: AsyncSession = Depends(get_db)) -> ActionResponse:
    """Run ANALYZE on the tracked tables.

    Updates planner statistics so query plans stay accurate after big
    ingestions. Doesn't lock; safe to run any time. We don't expose
    VACUUM FULL because it takes an ACCESS EXCLUSIVE lock.
    """
    try:
        # ANALYZE has to run outside an explicit transaction. Use the raw
        # connection and AUTOCOMMIT for the duration.
        raw = await db.connection()
        await raw.execute(text("COMMIT"))
        for tbl in _TRACKED_TABLES:
            await raw.execute(text(f'ANALYZE "{tbl}"'))
        return ActionResponse(
            ok=True,
            detail=f"ANALYZE 완료 ({len(_TRACKED_TABLES)}개 테이블).",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ANALYZE 실패: {e}")


@router.post(
    "/meili/drop",
    response_model=ActionResponse,
    response_model_by_alias=True,
)
async def meili_drop() -> ActionResponse:
    """Delete the Meili index entirely.

    Use when the index is corrupted or the schema has drifted so far
    that incremental fixes don't help. The next backend startup will
    re-create the index (empty) via ``ensure_index()``; the operator
    must follow up with ``python -m scripts.reindex_meili`` to
    repopulate from Postgres.
    """
    s = get_settings()

    def _drop() -> int:
        client = meili_client()
        try:
            stats = client.index(s.meili_index).get_stats()
            count = getattr(stats, "number_of_documents", None) or (
                stats.get("numberOfDocuments") if isinstance(stats, dict) else 0
            )
        except Exception:
            count = 0
        client.delete_index(s.meili_index)
        return int(count or 0)

    try:
        before = await asyncio.to_thread(_drop)
        return ActionResponse(
            ok=True,
            detail=(
                f"Meili 인덱스 '{s.meili_index}' 를 삭제했습니다 "
                f"(이전 문서 {before}개). "
                "다음 백엔드 시작 시 빈 인덱스가 다시 만들어지며, "
                "재색인을 위해 'python -m scripts.reindex_meili' 를 실행해 주세요."
            ),
            payload={"document_count_before": before},
        )
    except meilisearch.errors.MeilisearchApiError as e:  # type: ignore[attr-defined]
        raise HTTPException(status_code=500, detail=f"Meili 인덱스 삭제 실패: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Meili 인덱스 삭제 실패: {e}")
