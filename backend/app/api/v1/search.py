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

import asyncio
import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.logging import get_logger
from app.models import (
    AffectedProduct,
    Vulnerability,
    VulnerabilityType,
    vulnerability_type_map,
)
from app.schemas.search import SearchResponse
from app.schemas.vulnerability import CamelModel, VulnerabilityListItem
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


_PRIORITY_KEYS = {"kev", "epss_high", "cvss_mid_epss_high", "cvss_high_epss_low"}


@router.get("", response_model=SearchResponse, response_model_by_alias=True)
async def search(
    q: str = Query("", description="Full-text query"),
    severity: list[str] = Query(default=[], alias="severity"),
    os: list[str] = Query(default=[], alias="os"),
    type: list[str] = Query(default=[], alias="type"),
    domain: list[str] = Query(default=[], alias="domain"),
    from_date: str | None = Query(default=None, alias="from"),
    to_date: str | None = Query(default=None, alias="to"),
    priority: str | None = Query(
        default=None,
        description=(
            "Priority tier filter — one of 'kev', 'epss_high', "
            "'cvss_mid_epss_high', 'cvss_high_epss_low'. Falls through to "
            "the PG path because Meilisearch doesn't index our KEV/EPSS "
            "signals."
        ),
    ),
    sort: SortKey = Query("newest"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> SearchResponse:
    """Full-text search via Meilisearch + Postgres fallback on failure.

    Priority-tier filter (``priority=...``) skips Meilisearch entirely
    because the KEV / EPSS signals aren't indexed there — handled by
    ``_pg_search`` which has direct column access."""
    offset = (page - 1) * page_size
    cve_pattern = _cve_id_ilike_pattern(q)

    priority_norm = priority if priority in _PRIORITY_KEYS else None
    if priority_norm:
        rows, total = await _pg_search(
            db, q, severity, os, type, domain, from_date, to_date, sort,
            page_size, offset, cve_pattern, priority=priority_norm,
        )
        return SearchResponse(
            items=[VulnerabilityListItem.model_validate(v) for v in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

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
            domains=domain or None,
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
            db, q, severity, os, type, domain, from_date, to_date, sort, page_size, offset, cve_pattern, priority=None,
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
    domain: list[str],
    from_date: str | None,
    to_date: str | None,
    sort: SortKey,
    limit: int,
    offset: int,
    cve_pattern: str | None,
    priority: str | None = None,
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
    if domain:
        # domains is a TEXT[] with a GIN index; && (overlap) lets the
        # planner use the index for "any of these chips matches".
        conds.append(Vulnerability.domains.op("&&")(domain))
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

    # Priority-tier predicates mirror dashboard/_tier_filters so the
    # "전체 보기" link from the PriorityOverviewPanel lands on the same
    # row set the panel was summarizing.
    if priority == "kev":
        conds.append(Vulnerability.kev_listed.is_(True))
    elif priority == "epss_high":
        conds.append(Vulnerability.epss_score >= 0.5)
        conds.append(Vulnerability.kev_listed.is_not(True))
    elif priority == "cvss_mid_epss_high":
        conds.append(Vulnerability.cvss_score >= 4.0)
        conds.append(Vulnerability.cvss_score < 7.0)
        conds.append(Vulnerability.epss_score >= 0.3)
        conds.append(Vulnerability.kev_listed.is_not(True))
    elif priority == "cvss_high_epss_low":
        conds.append(Vulnerability.cvss_score >= 7.0)
        conds.append(
            or_(Vulnerability.epss_score < 0.3, Vulnerability.epss_score.is_(None))
        )
        conds.append(Vulnerability.kev_listed.is_not(True))

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


# ---------------------------------------------------------------------------
# Facet counts — drives dynamic filter chip lists
# ---------------------------------------------------------------------------


class FacetBucket(CamelModel):
    value: str
    count: int


class FacetsResponse(CamelModel):
    # Authoritative total over the whole vulnerabilities table — facet
    # bucket sums (severities/types/etc.) often *underrepresent* this
    # because they exclude NULLs (severity), or *overrepresent* (types
    # is M:N — one CVE can carry multiple labels). Always render
    # absolute counts against this number.
    total: int = 0
    types: list[FacetBucket] = []
    os_families: list[FacetBucket] = []
    severities: list[FacetBucket] = []
    sources: list[FacetBucket] = []
    domains: list[FacetBucket] = []
    # PublishedAt boundaries across the whole corpus — drives the
    # "데이터 YYYY.MM.DD ~ YYYY.MM.DD" tag on the dashboard so the
    # operator can see the time window the visible counts cover.
    earliest_published_at: datetime | None = None
    latest_published_at: datetime | None = None


# Facets change at ingestion frequency (~every 30 min by the scheduler),
# not per-request. Frontend FilterPanel + CorpusRange + future surfaces
# all hit /search/facets — a 60s TTL cache turns N concurrent requests
# into one DB round-trip without staleness anyone notices.
# 5분 캐시 — facets 는 ingestion 빈도(~30분)보다 훨씬 자주 안 바뀌고
# 같은 (window, filter) 조합으로 N concurrent 요청이 와도 한 번만 계산.
_FACETS_CACHE: dict[str, tuple[float, "FacetsResponse"]] = {}
_FACETS_CACHE_TTL = 300.0
_FACETS_CACHE_LOCK = asyncio.Lock()


@router.get(
    "/facets",
    response_model=FacetsResponse,
    response_model_by_alias=True,
)
async def search_facets(
    db: AsyncSession = Depends(get_db),
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    type: str | None = Query(default=None),
    domain: str | None = Query(default=None),
) -> FacetsResponse:
    """Facet aggregates, optionally narrowed by ``published_at`` window and
    by cross-filter selections.

    Date params are ISO-8601 (YYYY-MM-DD or full ISO). The filter params
    (severity/source/type/domain) implement self-exclusive cross-filtering:
    each facet's own dimension is excluded from filtering so the user can
    switch the active selection without first clearing it. All other
    facets apply every active filter.

    Cache key includes every param so consecutive requests for the same
    (window, filter) combination hit the cache while different
    combinations compute independently.
    """
    import time as _time
    now = _time.monotonic()
    since = _parse_iso_date(from_)
    until = _parse_iso_date(to)
    cache_key = (
        f"v3|{from_ or ''}|{to or ''}|"
        f"{severity or ''}|{source or ''}|{type or ''}|{domain or ''}"
    )
    cached = _FACETS_CACHE.get(cache_key)
    if cached and now - cached[0] < _FACETS_CACHE_TTL:
        return cached[1]
    async with _FACETS_CACHE_LOCK:
        cached = _FACETS_CACHE.get(cache_key)
        if cached and now - cached[0] < _FACETS_CACHE_TTL:
            return cached[1]
        result = await _build_facets(
            db,
            since=since,
            until=until,
            severity=severity or None,
            source=source or None,
            type_=type or None,
            domain=domain or None,
        )
        _FACETS_CACHE[cache_key] = (now, result)
        return result


def _parse_iso_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # Accept either YYYY-MM-DD or full ISO (with Z or offset).
        if len(s) == 10:
            return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _build_facets(
    db: AsyncSession,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    severity: str | None = None,
    source: str | None = None,
    type_: str | None = None,
    domain: str | None = None,
) -> FacetsResponse:
    """Filter facet counts derived from the parsed CVE corpus.

    Replaces hardcoded chip lists in the frontend — chips are rendered
    only for values that actually have rows in DB, with the count shown
    next to the label so users can see "RCE (1234)" before clicking.
    Empty buckets simply don't appear, fixing the long-standing bug
    where users could click a chip (e.g. ``Path-Traversal``) for which
    ingestion had never produced a label.

    Each facet runs a single GROUP BY against its source table; on the
    current scale (~75k vulns / 247 mappings / ~250k affected_products)
    these complete in a handful of milliseconds.

    When ``since`` or ``until`` are passed we narrow on
    ``Vulnerability.published_at`` — for cross-table facets (types / os
    / domains) we JOIN through Vulnerability so the window applies to
    each row's underlying CVE date, not the join row itself.
    """
    # Window filter — builds a list of conditions applied to every query.
    def _date_window(col):
        conds = []
        if since is not None:
            conds.append(col >= since)
        if until is not None:
            conds.append(col <= until)
        return conds

    # Self-exclusive cross-filter: each facet excludes its own dimension
    # so users can re-pick within a category without clearing first.
    #
    # ``vuln_filter_for(exclude=<dim>)`` returns the conjunctive WHERE
    # clauses that should be applied to a query whose facet is over
    # ``<dim>``. The date window is always applied; severity/source apply
    # as direct column predicates; type/domain apply via EXISTS subqueries
    # so they don't fan out the GROUP BY count.
    def vuln_filter_for(exclude: str | None = None) -> list:
        conds = list(_date_window(Vulnerability.published_at))
        if severity and exclude != "severity":
            conds.append(Vulnerability.severity == severity)
        if source and exclude != "source":
            # 커버리지 기준: 주 소스(source)가 아니라 sources 배열에 해당 소스가
            # 들어 있으면 매칭(예: MITRE 가 주 소스여도 GHSA 가 보고했으면 GHSA 클릭에
            # 잡힘). 아래 source facet 도 unnest(sources) 로 세므로 칩 카운트와 일치.
            conds.append(Vulnerability.sources.any(source))
        if type_ and exclude != "type":
            conds.append(
                select(1)
                .select_from(vulnerability_type_map)
                .join(
                    VulnerabilityType,
                    VulnerabilityType.id == vulnerability_type_map.c.type_id,
                )
                .where(
                    vulnerability_type_map.c.vulnerability_id == Vulnerability.id,
                    VulnerabilityType.name == type_,
                )
                .exists()
            )
        if domain and exclude != "domain":
            conds.append(Vulnerability.domains.any(domain))
        return conds

    # types — JOIN map → types → vulnerabilities; exclude=type for self.
    type_conds = vuln_filter_for(exclude="type")
    type_q = (
        select(
            VulnerabilityType.name,
            func.count(func.distinct(vulnerability_type_map.c.vulnerability_id)).label("c"),
        )
        .join(
            vulnerability_type_map,
            vulnerability_type_map.c.type_id == VulnerabilityType.id,
        )
        .join(
            Vulnerability,
            Vulnerability.id == vulnerability_type_map.c.vulnerability_id,
        )
        .where(*type_conds)
    )
    # 캐시 TTL 5분 + alembic 0022 의 인덱스 (severity / source / domains GIN /
    # affected_products(vuln_id, os_family)) 로 query 자체가 빠름.
    # AsyncSession 은 single connection 이라 asyncio.gather 로 6개 query 를
    # 병렬화하기는 어려움 — 별 engine connection 필요. 단순 sequential 유지.
    type_rows = (
        await db.execute(
            type_q.group_by(VulnerabilityType.name).order_by(func.count().desc())
        )
    ).all()

    # os families — JOIN through Vulnerability so all filters apply.
    os_conds = vuln_filter_for(exclude=None)
    os_q = (
        select(
            AffectedProduct.os_family,
            func.count(func.distinct(AffectedProduct.vulnerability_id)).label("c"),
        )
        .join(
            Vulnerability,
            Vulnerability.id == AffectedProduct.vulnerability_id,
        )
        .where(*os_conds)
    )
    os_rows = (
        await db.execute(os_q.group_by(AffectedProduct.os_family).order_by(func.count().desc()))
    ).all()

    # severities — exclude=severity for self.
    sev_conds = vuln_filter_for(exclude="severity")
    sev_rows = (
        await db.execute(
            select(Vulnerability.severity, func.count())
            .where(
                Vulnerability.severity.isnot(None),
                *sev_conds,
            )
            .group_by(Vulnerability.severity)
            .order_by(func.count().desc())
        )
    ).all()

    # sources — 커버리지 기준(소스별 기여). 주 소스 1개(Vulnerability.source)가
    # 아니라 sources 배열을 unnest 해 각 소스가 보고한 CVE 수를 센다. MITRE 가
    # 캐노니컬이라 거의 모든 CVE 의 주 소스를 차지해 GHSA/NVD 가 0~2% 로 보이던
    # 오해를 해소(한 CVE 가 여러 소스에 잡혀 합계는 100% 초과 = 중복 카운트).
    # exclude=source for self.
    src_conds = vuln_filter_for(exclude="source")
    src_q = (
        select(
            func.unnest(Vulnerability.sources).label("s"),
            func.count(),
        )
        .where(*src_conds)
        .group_by("s")
        .order_by(func.count().desc())
    )
    src_rows = (await db.execute(src_q)).all()

    # domains — TEXT[] unnested; exclude=domain for self.
    dom_conds = vuln_filter_for(exclude="domain")
    dom_q = (
        select(
            func.unnest(Vulnerability.domains).label("d"),
            func.count(),
        )
        .where(*dom_conds)
        .group_by("d")
        .order_by(func.count().desc())
    )
    dom_rows = (await db.execute(dom_q)).all()

    def _enum_value(v) -> str:
        return v.value if hasattr(v, "value") else str(v)

    # publishedAt boundaries — MIN/MAX over the (filtered) window so the
    # header shows the actual span of the visible aggregation. Includes
    # every active cross-filter so the displayed range matches the chart.
    bounds_q = select(
        func.min(Vulnerability.published_at),
        func.max(Vulnerability.published_at),
    ).where(
        Vulnerability.published_at.isnot(None),
        *vuln_filter_for(exclude=None),
    )
    bounds = (await db.execute(bounds_q)).first()
    earliest = bounds[0] if bounds else None
    latest = bounds[1] if bounds else None

    # Authoritative total — applies every active cross-filter so the
    # header total matches the union of facet rings exactly.
    total_q = (
        select(func.count())
        .select_from(Vulnerability)
        .where(*vuln_filter_for(exclude=None))
    )
    total = (await db.execute(total_q)).scalar_one()

    return FacetsResponse(
        total=int(total or 0),
        types=[FacetBucket(value=str(n), count=int(c)) for n, c in type_rows],
        os_families=[FacetBucket(value=_enum_value(o), count=int(c)) for o, c in os_rows],
        severities=[FacetBucket(value=_enum_value(s), count=int(c)) for s, c in sev_rows],
        sources=[FacetBucket(value=str(s), count=int(c)) for s, c in src_rows if s],
        domains=[FacetBucket(value=str(d), count=int(c)) for d, c in dom_rows if d],
        earliest_published_at=earliest,
        latest_published_at=latest,
    )
