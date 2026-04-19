from datetime import datetime, timezone

from fastapi import APIRouter, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.core.database import get_db
from app.core.logging import get_logger
from app.models import Vulnerability
from app.schemas.search import SearchResponse
from app.schemas.vulnerability import VulnerabilityListItem
from app.services import search_service

router = APIRouter(prefix="/search", tags=["search"])
log = get_logger(__name__)


def _parse_date_to_ts(s: str | None) -> int | None:
    if not s:
        return None
    try:
        return int(datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


@router.get("", response_model=SearchResponse, response_model_by_alias=True)
async def search(
    q: str = Query("", description="Full-text query"),
    severity: list[str] = Query(default=[], alias="severity"),
    os: list[str] = Query(default=[], alias="os"),
    type: list[str] = Query(default=[], alias="type"),
    from_date: str | None = Query(default=None, alias="from"),
    to_date: str | None = Query(default=None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> SearchResponse:
    """Full-text search via Meilisearch + Postgres fallback on failure."""
    offset = (page - 1) * page_size

    try:
        ms = search_service.search(
            q,
            severity=severity or None,
            os_family=os or None,
            types=type or None,
            from_ts=_parse_date_to_ts(from_date),
            to_ts=_parse_date_to_ts(to_date),
            limit=page_size,
            offset=offset,
        )
        # Hydrate by cve_id from Postgres to get full relation payload
        cve_ids = [hit["cveId"] for hit in ms.get("hits", []) if "cveId" in hit]
        if cve_ids:
            rows = (
                (await db.execute(
                    select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids))
                ))
                .scalars()
                .unique()
                .all()
            )
            # Preserve Meilisearch's relevance order
            order = {cid: i for i, cid in enumerate(cve_ids)}
            rows.sort(key=lambda v: order.get(v.cve_id, 9999))
        else:
            rows = []
        total = ms.get("estimatedTotalHits", len(rows))
        return SearchResponse(
            items=[VulnerabilityListItem.model_validate(v) for v in rows],
            total=total,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        log.warning("search.meili_fallback", error=str(exc))
        # Fallback: Postgres tsvector
        rows, total = await _pg_search(db, q, severity, os, type, from_date, to_date, page_size, offset)
        return SearchResponse(
            items=[VulnerabilityListItem.model_validate(v) for v in rows],
            total=total,
            page=page,
            page_size=page_size,
        )


async def _pg_search(
    db: AsyncSession,
    q: str,
    severity: list[str],
    os: list[str],
    type_: list[str],
    from_date: str | None,
    to_date: str | None,
    limit: int,
    offset: int,
) -> tuple[list[Vulnerability], int]:
    from sqlalchemy import and_, func

    from app.models import AffectedProduct, VulnerabilityType, vulnerability_type_map

    stmt = select(Vulnerability)
    conds = []
    if q:
        conds.append(Vulnerability.search_vector.op("@@")(func.websearch_to_tsquery("simple", q)))
    if severity:
        conds.append(Vulnerability.severity.in_(severity))
    if os:
        # EXISTS keeps duplicate-free results without DISTINCT cost
        sub = select(AffectedProduct.id).where(
            AffectedProduct.vulnerability_id == Vulnerability.id,
            AffectedProduct.os_family.in_(os),
        )
        conds.append(sub.exists())
    if type_:
        sub = (
            select(vulnerability_type_map.c.vulnerability_id)
            .join(VulnerabilityType, VulnerabilityType.id == vulnerability_type_map.c.type_id)
            .where(
                vulnerability_type_map.c.vulnerability_id == Vulnerability.id,
                VulnerabilityType.name.in_(type_),
            )
        )
        conds.append(sub.exists())
    if from_date:
        try:
            conds.append(Vulnerability.published_at >= datetime.fromisoformat(from_date).replace(tzinfo=timezone.utc))
        except ValueError:
            pass
    if to_date:
        try:
            conds.append(Vulnerability.published_at <= datetime.fromisoformat(to_date).replace(tzinfo=timezone.utc))
        except ValueError:
            pass

    if conds:
        stmt = stmt.where(and_(*conds))

    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        (
            await db.execute(
                stmt.order_by(Vulnerability.published_at.desc().nulls_last())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .unique()
        .all()
    )
    return rows, total
