"""Asset → CVE matching.

The client keeps user assets in localStorage (no login, no server-side
persistence) and posts them here to discover which parsed CVEs affect the
user's stack. Matching is ILIKE-based on vendor/product — version_range
is returned in the payload for the client to surface, but we don't attempt
strict semver range checks server-side (CPE version_range is free-form text).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import AffectedProduct, Vulnerability
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
