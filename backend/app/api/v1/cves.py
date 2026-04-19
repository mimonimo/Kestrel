from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Vulnerability
from app.schemas.vulnerability import VulnerabilityDetail, VulnerabilityListItem

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("", response_model=list[VulnerabilityListItem], response_model_by_alias=True)
async def list_cves(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[Vulnerability]:
    """Recent vulnerabilities, newest first. Falls back to DB when the search
    service isn't the right fit (e.g. no query/filters).
    """
    stmt = (
        select(Vulnerability)
        .order_by(Vulnerability.published_at.desc().nulls_last())
        .limit(limit)
        .offset(offset)
    )
    return (await db.execute(stmt)).scalars().unique().all()


@router.get("/batch", response_model=list[VulnerabilityListItem], response_model_by_alias=True)
async def batch_cves(
    ids: str = Query(..., description="Comma-separated CVE IDs"),
    db: AsyncSession = Depends(get_db),
) -> list[Vulnerability]:
    """Fetch a list of CVEs by ID — used by the client-side bookmarks filter
    so we don't make one round-trip per bookmark."""
    parsed = [s.strip() for s in ids.split(",") if s.strip()][:200]
    if not parsed:
        return []
    rows = (
        (await db.execute(select(Vulnerability).where(Vulnerability.cve_id.in_(parsed))))
        .scalars()
        .unique()
        .all()
    )
    order = {cid: i for i, cid in enumerate(parsed)}
    rows.sort(key=lambda v: order.get(v.cve_id, 9999))
    return rows


@router.get("/{cve_id}", response_model=VulnerabilityDetail, response_model_by_alias=True)
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)) -> Vulnerability:
    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    return vuln
