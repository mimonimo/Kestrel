"""Bookmarks API — anonymous, scoped by `X-Client-Id` header.

The browser generates a UUID once and stores it in localStorage; subsequent
requests echo it back via the `X-Client-Id` header. There's no auth, so this
key is the only ownership signal — it's deliberately opaque.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Bookmark
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/bookmarks", tags=["bookmarks"])


class BookmarkCreate(CamelModel):
    cve_id: str = Field(min_length=3, max_length=32)


class BookmarkOut(CamelModel):
    cve_id: str


class BookmarkListResponse(CamelModel):
    items: list[BookmarkOut]
    total: int


def _require_client(x_client_id: str | None) -> str:
    if not x_client_id or len(x_client_id) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Client-Id header is required",
        )
    return x_client_id


@router.get("", response_model=BookmarkListResponse, response_model_by_alias=True)
async def list_bookmarks(
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> BookmarkListResponse:
    cid = _require_client(x_client_id)
    rows = (
        await db.execute(
            select(Bookmark.cve_id)
            .where(Bookmark.client_id == cid)
            .order_by(Bookmark.created_at.desc())
        )
    ).all()
    items = [BookmarkOut(cve_id=r[0]) for r in rows]
    return BookmarkListResponse(items=items, total=len(items))


@router.post("", response_model=BookmarkOut, response_model_by_alias=True, status_code=201)
async def add_bookmark(
    body: BookmarkCreate,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> BookmarkOut:
    cid = _require_client(x_client_id)
    bm = Bookmark(client_id=cid, cve_id=body.cve_id)
    db.add(bm)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()  # already bookmarked — idempotent
    return BookmarkOut(cve_id=body.cve_id)


@router.delete("/{cve_id}", status_code=204)
async def remove_bookmark(
    cve_id: str,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> None:
    cid = _require_client(x_client_id)
    await db.execute(
        delete(Bookmark).where(Bookmark.client_id == cid, Bookmark.cve_id == cve_id)
    )
    await db.commit()
