"""Search endpoint — Meilisearch primary, Postgres tsvector fallback.

PR-A (Step 10) additions
------------------------
- ``sort`` query parameter pushes ordering down to the engine instead of
  re-sorting the visible page on the client. The frontend's previous
  client-side ``sortVulnerabilities()`` only saw 20 items at a time and
  silently lied about ordering across pages.
- ``_cve_id_ilike_pattern()`` detects digit/dash-only inputs like
  "44228", "2021-44", "CVE-2024-3" and surfaces matching cve_id rows on
  page 1 ahead of full-text hits. Both the Meili path (via a Postgres
  pre-lookup) and the PG fallback (via ``OR cve_id ILIKE``) honor it,
  so digit-only search is reliable regardless of which engine is up.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.logging import get_logger
from app.models import Vulnerability
from app.schemas.search import SearchResponse
from app.schemas.vulnerability import VulnerabilityListItem
from app.services import search_service

router = APIRouter(prefix="/search", tags=["search"])
log = get_logger(__name__)


SortKey = Literal["newest", "oldest", "severity", "cvss"]


def _parse_date_to_ts(s: str | None) -> int | None:
    if not s:
        return None
    try:
        return int(datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


_CVE_PARTIAL_RE = re.compile(r"^[0-9-]{3,}$")


def _cve_id_ilike_pattern(q: str) -> str | None:
    """Detect CVE-id-shaped fragments (digits + dashes, optional 'CVE-'
    prefix, ≥3 chars) and return an ILIKE pattern that matches inside
    ``cve_id``.

    Examples
    --------
    "44228"        → "%CVE-%44228%"     (matches CVE-2021-44228, CVE-2024-44228, …)
    "2021-44228"   → "%CVE-%2021-44228%"
    "CVE-2021"     → "%CVE-%2021%"
    "2021-44"      → "%CVE-%2021-44%"   (matches CVE-2021-44XX)
    "log4j"        → None               (not CVE-id-shaped, full-text path handles it)

    Returns ``None`` when the input doesn't look like a CVE-id fragment so
    we don't pollute generic queries with overly broad ILIKE matches.
    """
    if not q:
        return None
    cleaned = q.strip().upper().replace(" ", "")
    if cleaned.startswith("CVE-"):
        cleaned = cleaned[4:]
    elif cleaned.startswith("CVE"):
        cleaned = cleaned[3:].lstrip("-")
    if not cleaned or not _CVE_PARTIAL_RE.match(cleaned):
        return None
    # Escape ILIKE wildcards so a literal % or _ in the (unlikely) input
    # doesn't widen the match.
    safe = cleaned.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
    return f"%CVE-%{safe}%"


def _severity_rank_case():
    """SQL CASE expression mapping severity enum → numeric rank (matches
    ``search_service.SEVERITY_RANK``). NULL severity → 0 so it sorts last
    under ``DESC NULLS LAST``."""
    return case(
        (Vulnerability.severity == "critical", 4),
        (Vulnerability.severity == "high", 3),
        (Vulnerability.severity == "medium", 2),
        (Vulnerability.severity == "low", 1),
        else_=0,
    )


def _pg_order_by(sort: SortKey):
    if sort == "oldest":
        return [Vulnerability.published_at.asc().nulls_last()]
    if sort == "severity":
        return [_severity_rank_case().desc(), Vulnerability.published_at.desc().nulls_last()]
    if sort == "cvss":
        return [Vulnerability.cvss_score.desc().nulls_last(), Vulnerability.published_at.desc().nulls_last()]
    return [Vulnerability.published_at.desc().nulls_last()]


@router.get("", response_model=SearchResponse, response_model_by_alias=True)
async def search(
    q: str = Query("", description="Full-text query"),
    severity: list[str] = Query(default=[], alias="severity"),
    os: list[str] = Query(default=[], alias="os"),
    type: list[str] = Query(default=[], alias="type"),
    from_date: str | None = Query(default=None, alias="from"),
    to_date: str | None = Query(default=None, alias="to"),
    sort: SortKey = Query("newest"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> SearchResponse:
    """Full-text search via Meilisearch + Postgres fallback on failure."""
    offset = (page - 1) * page_size
    cve_pattern = _cve_id_ilike_pattern(q)

    # Always do a fast cve_id lookup when the query is CVE-id-shaped — it's
    # cheap (unique index on cve_id), authoritative, and the result is
    # merged into both the Meili and PG paths so the user sees the same
    # ordering regardless of which engine is healthy. Limited to a small
    # number because we only prepend on page 1.
    priority_ids: list[str] = []
    if cve_pattern and page == 1:
        priority_rows = (
            await db.execute(
                select(Vulnerability.cve_id)
                .where(Vulnerability.cve_id.ilike(cve_pattern))
                .order_by(Vulnerability.published_at.desc().nulls_last())
                .limit(page_size)
            )
        ).scalars().all()
        priority_ids = list(priority_rows)

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
            sort=sort,
        )
        meili_ids = [hit["cveId"] for hit in ms.get("hits", []) if "cveId" in hit]
        # Prepend priority CVE-id matches that aren't already in the meili
        # page; trim the tail so the page size stays stable.
        seen = set(priority_ids)
        merged = priority_ids + [cid for cid in meili_ids if cid not in seen]
        merged = merged[:page_size]
        rows = await _hydrate_in_order(db, merged)
        total = max(ms.get("estimatedTotalHits", len(rows)), len(priority_ids))
        return SearchResponse(
            items=[VulnerabilityListItem.model_validate(v) for v in rows],
            total=total,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        log.warning("search.meili_fallback", error=str(exc))
        rows, total = await _pg_search(
            db, q, severity, os, type, from_date, to_date, sort, page_size, offset, cve_pattern
        )
        return SearchResponse(
            items=[VulnerabilityListItem.model_validate(v) for v in rows],
            total=total,
            page=page,
            page_size=page_size,
        )


async def _hydrate_in_order(db: AsyncSession, cve_ids: list[str]) -> list[Vulnerability]:
    """Fetch full Vulnerability rows for the given cve_ids, preserving the
    given order (Meili relevance / cveId-prepend order)."""
    if not cve_ids:
        return []
    rows = (
        (await db.execute(select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids))))
        .scalars()
        .unique()
        .all()
    )
    order = {cid: i for i, cid in enumerate(cve_ids)}
    rows.sort(key=lambda v: order.get(v.cve_id, 9999))
    return rows


async def _pg_search(
    db: AsyncSession,
    q: str,
    severity: list[str],
    os: list[str],
    type_: list[str],
    from_date: str | None,
    to_date: str | None,
    sort: SortKey,
    limit: int,
    offset: int,
    cve_pattern: str | None,
) -> tuple[list[Vulnerability], int]:
    from sqlalchemy import and_, func

    from app.models import AffectedProduct, VulnerabilityType, vulnerability_type_map

    stmt = select(Vulnerability)
    conds = []
    if q:
        # The text search OR cve_id ILIKE pattern union — partial CVE-id
        # inputs match both the tsvector index and the literal cve_id
        # column, so "44228" finds CVE-2021-44228 even when tsvector
        # tokenization happens to drop digit-only fragments.
        text_cond = Vulnerability.search_vector.op("@@")(
            func.websearch_to_tsquery("simple", q)
        )
        if cve_pattern:
            conds.append(or_(text_cond, Vulnerability.cve_id.ilike(cve_pattern)))
        else:
            conds.append(text_cond)
    if severity:
        conds.append(Vulnerability.severity.in_(severity))
    if os:
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
            conds.append(
                Vulnerability.published_at >= datetime.fromisoformat(from_date).replace(tzinfo=timezone.utc)
            )
        except ValueError:
            pass
    if to_date:
        try:
            conds.append(
                Vulnerability.published_at <= datetime.fromisoformat(to_date).replace(tzinfo=timezone.utc)
            )
        except ValueError:
            pass

    if conds:
        stmt = stmt.where(and_(*conds))

    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        (
            await db.execute(
                stmt.order_by(*_pg_order_by(sort)).limit(limit).offset(offset)
            )
        )
        .scalars()
        .unique()
        .all()
    )
    return rows, total
