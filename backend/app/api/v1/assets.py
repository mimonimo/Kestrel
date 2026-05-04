"""Asset → CVE matching.

The client keeps user assets in localStorage (no login, no server-side
persistence) and posts them here to discover which parsed CVEs affect the
user's stack. Matching is ILIKE-based on vendor/product — version_range
is returned in the payload for the client to surface, but we don't attempt
strict semver range checks server-side (CPE version_range is free-form text).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import AffectedProduct, OsFamily, Vulnerability
from app.schemas.search import SearchResponse
from app.schemas.vulnerability import CamelModel, VulnerabilityListItem

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetInput(CamelModel):
    vendor: str = Field(min_length=1, max_length=120)
    product: str = Field(min_length=1, max_length=200)
    version: str | None = None


class MatchRequest(CamelModel):
    assets: list[AssetInput] = Field(default_factory=list, max_length=50)
    limit: int = Field(default=100, ge=1, le=500)


class NotificationsRequest(CamelModel):
    assets: list[AssetInput] = Field(default_factory=list, max_length=50)
    # Default window is 14 days — long enough to catch a returning user
    # who only opens the dashboard biweekly, short enough that the JOIN
    # against affected_products + vulnerabilities stays cheap.
    since_days: int = Field(default=14, ge=1, le=365)
    limit: int = Field(default=50, ge=1, le=200)


class CatalogEntry(CamelModel):
    vendor: str
    product: str
    os_family: OsFamily
    cve_count: int
    sample_versions: list[str] = []


class CatalogResponse(CamelModel):
    items: list[CatalogEntry]


@router.get("/catalog", response_model=CatalogResponse, response_model_by_alias=True)
async def asset_catalog(
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> CatalogResponse:
    """Browse the parsed (vendor, product, os_family) catalog.

    Used by the settings UI as an autocomplete source so user-entered
    asset rows match what the ingestor actually stored.
    """
    cve_count = func.count(func.distinct(AffectedProduct.vulnerability_id)).label("cve_count")
    base = select(
        AffectedProduct.vendor,
        AffectedProduct.product,
        AffectedProduct.os_family,
        cve_count,
    )
    if q:
        like = f"%{q.strip().lower()}%"
        base = base.where(
            or_(
                func.lower(AffectedProduct.vendor).like(like),
                func.lower(AffectedProduct.product).like(like),
                func.lower(AffectedProduct.cpe_string).like(like),
            )
        )
    base = (
        base.group_by(AffectedProduct.vendor, AffectedProduct.product, AffectedProduct.os_family)
        .order_by(desc(cve_count))
        .limit(limit)
    )
    rows = (await db.execute(base)).all()
    if not rows:
        return CatalogResponse(items=[])

    pairs = [(r.vendor, r.product) for r in rows]
    ver_stmt = (
        select(
            AffectedProduct.vendor,
            AffectedProduct.product,
            AffectedProduct.version_range,
            func.count().label("n"),
        )
        .where(
            AffectedProduct.version_range.isnot(None),
            or_(
                *[
                    (AffectedProduct.vendor == v) & (AffectedProduct.product == p)
                    for v, p in pairs
                ]
            ),
        )
        .group_by(
            AffectedProduct.vendor, AffectedProduct.product, AffectedProduct.version_range
        )
        .order_by(desc("n"))
    )
    by_pair: dict[tuple[str, str], list[str]] = {}
    for v, p, ver, _ in (await db.execute(ver_stmt)).all():
        if not ver:
            continue
        by_pair.setdefault((v, p), [])
        if len(by_pair[(v, p)]) < 5 and ver not in by_pair[(v, p)]:
            by_pair[(v, p)].append(ver)

    return CatalogResponse(
        items=[
            CatalogEntry(
                vendor=r.vendor,
                product=r.product,
                os_family=r.os_family,
                cve_count=r.cve_count,
                sample_versions=by_pair.get((r.vendor, r.product), []),
            )
            for r in rows
        ]
    )


@router.post("/match", response_model=SearchResponse, response_model_by_alias=True)
async def match_assets(req: MatchRequest, db: AsyncSession = Depends(get_db)) -> SearchResponse:
    if not req.assets:
        return SearchResponse(items=[], total=0, page=1, page_size=req.limit)

    # Build an OR of (vendor ILIKE ? AND product ILIKE ?) clauses.
    clauses = []
    for a in req.assets:
        clauses.append(
            (AffectedProduct.vendor.ilike(a.vendor))
            & (AffectedProduct.product.ilike(a.product))
        )

    sub = select(AffectedProduct.vulnerability_id).where(or_(*clauses)).distinct()
    stmt = (
        select(Vulnerability)
        .where(Vulnerability.id.in_(sub))
        .options(
            selectinload(Vulnerability.types),
            selectinload(Vulnerability.affected_products),
        )
        .order_by(Vulnerability.published_at.desc().nulls_last())
        .limit(req.limit)
    )
    rows = (await db.execute(stmt)).scalars().unique().all()

    return SearchResponse(
        items=[VulnerabilityListItem.model_validate(v) for v in rows],
        total=len(rows),
        page=1,
        page_size=req.limit,
    )


@router.post(
    "/notifications",
    response_model=SearchResponse,
    response_model_by_alias=True,
)
async def asset_notifications(
    req: NotificationsRequest, db: AsyncSession = Depends(get_db),
) -> SearchResponse:
    """Recent CVEs (within last ``since_days``) that match the caller's
    assets. Powers the in-app notification bell.

    Same matching shape as ``/assets/match`` but adds the recency filter
    on ``published_at`` so the bell surfaces *new* matches rather than
    the entire historical set. Sorted newest first so the dropdown's
    top entry is always the one the user hasn't seen yet.

    Stateless — read state lives in the client's localStorage as a
    ``lastSeenAt`` ISO string compared against each item's
    ``publishedAt``.
    """
    if not req.assets:
        return SearchResponse(items=[], total=0, page=1, page_size=req.limit)

    cutoff = datetime.now(timezone.utc) - timedelta(days=req.since_days)
    clauses = [
        (AffectedProduct.vendor.ilike(a.vendor))
        & (AffectedProduct.product.ilike(a.product))
        for a in req.assets
    ]
    sub = select(AffectedProduct.vulnerability_id).where(or_(*clauses)).distinct()
    stmt = (
        select(Vulnerability)
        .where(
            Vulnerability.id.in_(sub),
            Vulnerability.published_at.isnot(None),
            Vulnerability.published_at >= cutoff,
        )
        .options(
            selectinload(Vulnerability.types),
            selectinload(Vulnerability.affected_products),
        )
        .order_by(Vulnerability.published_at.desc())
        .limit(req.limit)
    )
    rows = (await db.execute(stmt)).scalars().unique().all()
    return SearchResponse(
        items=[VulnerabilityListItem.model_validate(v) for v in rows],
        total=len(rows),
        page=1,
        page_size=req.limit,
    )
