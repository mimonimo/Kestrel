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

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import AffectedProduct, OsFamily, User, UserAsset, Vulnerability
from app.schemas.search import SearchResponse
from app.schemas.vulnerability import CamelModel, VulnerabilityListItem

router = APIRouter(prefix="/assets", tags=["assets"])


def _to_ilike(pattern: str) -> str:
    """사용자 자산 패턴 → SQL ILIKE 패턴.

    와일드카드 ``*`` 를 SQL ``%`` 로 변환해 ``goo*`` 같은 접두 매칭을 지원한다.
    리터럴 ``%``/``_`` 는 이스케이프(우리 카탈로그 벤더/제품엔 거의 없지만 안전).
    ``*`` 가 없으면 정확 일치(기존 동작 유지).
    """
    escaped = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%")


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


class VendorEntry(CamelModel):
    vendor: str
    cve_count: int


class VendorsResponse(CamelModel):
    items: list[VendorEntry]


class ProductEntry(CamelModel):
    product: str
    cve_count: int
    os_families: list[str] = []


class ProductsResponse(CamelModel):
    items: list[ProductEntry]


@router.get("/vendors", response_model=VendorsResponse, response_model_by_alias=True)
async def list_vendors(
    starts_with: str = Query(..., min_length=1, max_length=2),
    limit: int = Query(default=300, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
) -> VendorsResponse:
    """A-Z 브라우즈 — 첫 글자별 벤더 목록(정규화 lower 기준 그룹). CVE 많은 순.

    ``starts_with`` 가 알파벳이면 해당 글자로 시작하는 벤더, ``#`` 등이면
    알파벳으로 시작하지 않는(숫자·기호) 벤더.
    """
    letter = starts_with.strip().lower()[:1]
    vlower = func.lower(AffectedProduct.vendor)
    cve_count = func.count(func.distinct(AffectedProduct.vulnerability_id)).label("cve_count")
    base = select(vlower.label("v"), func.min(AffectedProduct.vendor).label("disp"), cve_count)
    if letter.isalpha():
        base = base.where(vlower.like(f"{letter}%"))
    else:
        base = base.where(vlower.op("~")("^[^a-z]"))
    base = base.group_by("v").order_by(desc(cve_count)).limit(limit)
    rows = (await db.execute(base)).all()
    return VendorsResponse(
        items=[VendorEntry(vendor=r.disp, cve_count=int(r.cve_count)) for r in rows]
    )


@router.get("/products", response_model=ProductsResponse, response_model_by_alias=True)
async def list_products(
    vendor: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(default=300, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
) -> ProductsResponse:
    """선택한 벤더(대소문자 무시)의 제품 목록 — 정규화 lower 기준 그룹, CVE 많은 순.
    각 제품의 OS 패밀리도 함께."""
    plower = func.lower(AffectedProduct.product)
    cve_count = func.count(func.distinct(AffectedProduct.vulnerability_id)).label("cve_count")
    os_agg = func.array_agg(func.distinct(AffectedProduct.os_family)).label("os")
    base = (
        select(plower.label("p"), func.min(AffectedProduct.product).label("disp"), cve_count, os_agg)
        .where(func.lower(AffectedProduct.vendor) == vendor.strip().lower())
        .group_by("p")
        .order_by(desc(cve_count))
        .limit(limit)
    )
    rows = (await db.execute(base)).all()
    items = []
    for r in rows:
        fams = [str(getattr(o, "value", o)) for o in (r.os or []) if o is not None]
        items.append(ProductEntry(product=r.disp, cve_count=int(r.cve_count), os_families=fams))
    return ProductsResponse(items=items)


@router.post("/match", response_model=SearchResponse, response_model_by_alias=True)
async def match_assets(req: MatchRequest, db: AsyncSession = Depends(get_db)) -> SearchResponse:
    if not req.assets:
        return SearchResponse(items=[], total=0, page=1, page_size=req.limit)

    # Build an OR of (vendor ILIKE ? AND product ILIKE ?) clauses.
    # ``*`` 와일드카드 지원 — _to_ilike 가 % 로 변환(goo* → goo%).
    clauses = []
    for a in req.assets:
        clauses.append(
            (AffectedProduct.vendor.ilike(_to_ilike(a.vendor), escape="\\"))
            & (AffectedProduct.product.ilike(_to_ilike(a.product), escape="\\"))
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
        (AffectedProduct.vendor.ilike(_to_ilike(a.vendor), escape="\\"))
        & (AffectedProduct.product.ilike(_to_ilike(a.product), escape="\\"))
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


# ── 서버 저장 자산 (로그인 사용자) — 알림의 전제 ─────────────────────
# 비로그인은 종전대로 localStorage + /match 로 동작(알림 없음). 로그인 사용자는
# 여기에 저장해야 수집 훅이 새 CVE 매칭 시 알림을 보낼 수 있다. (PR 10-FB)


class SavedAsset(CamelModel):
    vendor: str
    product: str


class SavedAssetsResponse(CamelModel):
    assets: list[SavedAsset]


class SaveAssetsRequest(CamelModel):
    # 전체 집합 교체(PUT 의미) — 프론트의 AssetsManager 가 현재 목록을 통째로 보낸다.
    assets: list[AssetInput] = Field(default_factory=list, max_length=200)


@router.get("/saved", response_model=SavedAssetsResponse, response_model_by_alias=True)
async def list_saved_assets(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> SavedAssetsResponse:
    rows = (
        await db.execute(
            select(UserAsset)
            .where(UserAsset.user_id == user.id)
            .order_by(UserAsset.vendor, UserAsset.product)
        )
    ).scalars().all()
    return SavedAssetsResponse(
        assets=[SavedAsset(vendor=r.vendor, product=r.product) for r in rows]
    )


@router.put("/saved", response_model=SavedAssetsResponse, response_model_by_alias=True)
async def replace_saved_assets(
    req: SaveAssetsRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SavedAssetsResponse:
    """로그인 사용자의 저장 자산을 요청 집합으로 교체. 중복(벤더·제품)은 제거."""
    # 정규화 + 중복 제거.
    seen: set[tuple[str, str]] = set()
    cleaned: list[tuple[str, str]] = []
    for a in req.assets:
        key = (a.vendor.strip(), a.product.strip())
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        cleaned.append(key)

    # 전량 교체 — 기존 행 삭제 후 재삽입(작은 집합이라 단순/안전).
    existing = (
        await db.execute(select(UserAsset).where(UserAsset.user_id == user.id))
    ).scalars().all()
    for row in existing:
        await db.delete(row)
    for vendor, product in cleaned:
        db.add(UserAsset(user_id=user.id, vendor=vendor, product=product))
    await db.commit()

    return SavedAssetsResponse(
        assets=[SavedAsset(vendor=v, product=p) for v, p in cleaned]
    )
