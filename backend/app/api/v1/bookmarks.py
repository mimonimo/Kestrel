"""Bookmarks API — 로그인 사용자 전용 (PR 10-CN).

기존 ``X-Client-Id`` 헤더 기반 익명 즐겨찾기는 deprecated. 마이그레이션 0020 으로
``user_id`` 컬럼이 추가되어, 신규 로우는 모두 로그인 사용자에게 귀속된다.
GET/POST/DELETE 모두 ``get_current_user`` 의존성으로 401 가드.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import Bookmark, User
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/bookmarks", tags=["bookmarks"])


class BookmarkCreate(CamelModel):
    cve_id: str = Field(min_length=3, max_length=32)


class BookmarkOut(CamelModel):
    cve_id: str


class BookmarkListResponse(CamelModel):
    items: list[BookmarkOut]
    total: int


@router.get("", response_model=BookmarkListResponse, response_model_by_alias=True)
async def list_bookmarks(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> BookmarkListResponse:
    rows = (
        await db.execute(
            select(Bookmark.cve_id)
            .where(Bookmark.user_id == user.id)
            .order_by(Bookmark.created_at.desc())
        )
    ).all()
    items = [BookmarkOut(cve_id=r[0]) for r in rows]
    return BookmarkListResponse(items=items, total=len(items))


@router.post("", response_model=BookmarkOut, response_model_by_alias=True, status_code=201)
async def add_bookmark(
    body: BookmarkCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> BookmarkOut:
    bm = Bookmark(user_id=user.id, cve_id=body.cve_id)
    db.add(bm)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()  # 중복 — idempotent
    return BookmarkOut(cve_id=body.cve_id)


@router.delete("/{cve_id}", status_code=204)
async def remove_bookmark(
    cve_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    await db.execute(
        delete(Bookmark).where(Bookmark.user_id == user.id, Bookmark.cve_id == cve_id)
    )
    await db.commit()


@router.head("/{cve_id}", status_code=status.HTTP_204_NO_CONTENT)
async def check_bookmark(
    cve_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """현재 사용자가 이 CVE 를 즐겨찾기 했는지 — 204 (있음) / 404 (없음)."""
    row = await db.scalar(
        select(Bookmark.id).where(
            Bookmark.user_id == user.id, Bookmark.cve_id == cve_id
        )
    )
    if row is None:
        raise HTTPException(status_code=404)
