"""분석 기록 조회/관리 (PR 10-CN).

- ``GET /me/analyses``                    — 내가 만든 분석 (로그인 필수)
- ``GET /community/analyses``             — 모든 사용자의 공개 분석 (비로그인 OK)
- ``GET /cves/{cve_id}/analyses``         — 특정 CVE 의 분석 히스토리 (비로그인 OK)
- ``GET /analyses/{id}``                  — 단건 본문 (public 이면 누구나, private 는 본인만)
- ``PATCH /analyses/{id}``                — visibility 변경 (본인만)
- ``DELETE /analyses/{id}``               — 본인만

응답에 저자 식별은 ``user_id`` 가 아니라 ``author = {username, nickname}`` 만 노출.
이메일·role 등은 절대 직렬화하지 않는다.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_current_user, get_optional_user
from app.core.database import get_db
from app.models import AnalysisResult, User
from app.schemas.vulnerability import CamelModel


class AuthorOut(CamelModel):
    username: str
    nickname: str | None = None


class AnalysisSummary(CamelModel):
    id: str
    cve_id: str
    category: str
    title: str | None
    visibility: str
    created_at: datetime
    author: AuthorOut
    excerpt: str  # 첫 240자 미리보기


class AnalysisDetail(AnalysisSummary):
    result_md: str
    prompt_md: str | None


class AnalysisList(CamelModel):
    items: list[AnalysisSummary]
    total: int


class AnalysisPatch(CamelModel):
    visibility: str | None = None
    title: str | None = None


def _excerpt(md: str, n: int = 240) -> str:
    flat = " ".join(md.split())
    return flat[:n] + ("…" if len(flat) > n else "")


def _to_summary(r: AnalysisResult) -> AnalysisSummary:
    author = AuthorOut(
        username=r.user.username if r.user else "(deleted)",
        nickname=r.user.nickname if r.user else None,
    )
    return AnalysisSummary(
        id=str(r.id),
        cve_id=r.cve_id,
        category=r.category,
        title=r.title,
        visibility=r.visibility,
        created_at=r.created_at,
        author=author,
        excerpt=_excerpt(r.result_md or ""),
    )


# ─── 내 분석 ────────────────────────────────────────────
me_router = APIRouter(prefix="/me", tags=["analysis-records"])


@me_router.get("/analyses", response_model=AnalysisList, response_model_by_alias=True)
async def list_my_analyses(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AnalysisList:
    q = (
        select(AnalysisResult)
        .where(AnalysisResult.user_id == user.id)
        .options(selectinload(AnalysisResult.user))
        .order_by(desc(AnalysisResult.created_at))
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(q)).scalars().all()
    return AnalysisList(items=[_to_summary(r) for r in rows], total=len(rows))


# ─── 공개 분석 (커뮤니티) ───────────────────────────────
community_router = APIRouter(prefix="/community", tags=["analysis-records"])


@community_router.get(
    "/analyses", response_model=AnalysisList, response_model_by_alias=True
)
async def list_community_analyses(
    db: AsyncSession = Depends(get_db),
    me: User | None = Depends(get_optional_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    cve_id: str | None = Query(default=None),
) -> AnalysisList:
    """모든 사용자의 ``public`` 분석. 본인 것은 자동 제외 (내 탭에서 보기 위함)."""
    q = (
        select(AnalysisResult)
        .where(AnalysisResult.visibility == "public")
        .options(selectinload(AnalysisResult.user))
        .order_by(desc(AnalysisResult.created_at))
    )
    if me is not None:
        q = q.where(AnalysisResult.user_id != me.id)
    if cve_id:
        q = q.where(AnalysisResult.cve_id == cve_id)
    q = q.limit(limit).offset(offset)
    rows = (await db.execute(q)).scalars().all()
    return AnalysisList(items=[_to_summary(r) for r in rows], total=len(rows))


# ─── CVE 별 분석 히스토리 ───────────────────────────────
cve_records_router = APIRouter(prefix="/cves", tags=["analysis-records"])


@cve_records_router.get(
    "/{cve_id}/analyses", response_model=AnalysisList, response_model_by_alias=True
)
async def list_cve_analyses(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    me: User | None = Depends(get_optional_user),
) -> AnalysisList:
    """이 CVE 의 분석 히스토리. public + (본인이면) 본인 private 포함."""
    visibility_filter = AnalysisResult.visibility == "public"
    if me is not None:
        from sqlalchemy import or_

        visibility_filter = or_(
            AnalysisResult.visibility == "public",
            AnalysisResult.user_id == me.id,
        )
    q = (
        select(AnalysisResult)
        .where(AnalysisResult.cve_id == cve_id, visibility_filter)
        .options(selectinload(AnalysisResult.user))
        .order_by(desc(AnalysisResult.created_at))
    )
    rows = (await db.execute(q)).scalars().all()
    return AnalysisList(items=[_to_summary(r) for r in rows], total=len(rows))


# ─── 단건 / 수정 / 삭제 ──────────────────────────────────
analyses_router = APIRouter(prefix="/analyses", tags=["analysis-records"])


async def _load(db: AsyncSession, analysis_id: str) -> AnalysisResult:
    try:
        aid = uuid.UUID(analysis_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="분석 기록을 찾을 수 없습니다.") from None
    row = await db.scalar(
        select(AnalysisResult)
        .where(AnalysisResult.id == aid)
        .options(selectinload(AnalysisResult.user))
    )
    if row is None:
        raise HTTPException(404, detail="분석 기록을 찾을 수 없습니다.")
    return row


@analyses_router.get(
    "/{analysis_id}", response_model=AnalysisDetail, response_model_by_alias=True
)
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    me: User | None = Depends(get_optional_user),
) -> AnalysisDetail:
    row = await _load(db, analysis_id)
    # private 면 본인만 본문 접근. 그 외 401.
    if row.visibility != "public" and (me is None or me.id != row.user_id):
        raise HTTPException(403, detail="비공개 분석입니다.")
    base = _to_summary(row)
    return AnalysisDetail(
        **base.model_dump(by_alias=False),
        result_md=row.result_md,
        prompt_md=row.prompt_md,
    )


@analyses_router.patch(
    "/{analysis_id}", response_model=AnalysisDetail, response_model_by_alias=True
)
async def update_analysis(
    analysis_id: str,
    body: AnalysisPatch,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AnalysisDetail:
    row = await _load(db, analysis_id)
    if row.user_id != user.id:
        raise HTTPException(403, detail="본인의 분석만 수정할 수 있습니다.")
    if body.visibility is not None:
        if body.visibility not in {"public", "private"}:
            raise HTTPException(400, detail="visibility 는 public 또는 private 만 가능합니다.")
        row.visibility = body.visibility
    if body.title is not None:
        row.title = body.title.strip() or None
    db.add(row)
    await db.commit()
    await db.refresh(row)
    base = _to_summary(row)
    return AnalysisDetail(
        **base.model_dump(by_alias=False),
        result_md=row.result_md,
        prompt_md=row.prompt_md,
    )


@analyses_router.delete("/{analysis_id}", status_code=204)
async def delete_analysis(
    analysis_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await _load(db, analysis_id)
    if row.user_id != user.id:
        raise HTTPException(403, detail="본인의 분석만 삭제할 수 있습니다.")
    await db.delete(row)
    await db.commit()
