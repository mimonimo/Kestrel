"""Community endpoints — anonymous posts and comments.

Ownership is tracked via `X-Client-Id` (the same browser-issued UUID used by
bookmarks). There is no auth — anyone can read; only the original `client_id`
can edit/delete what they wrote.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Comment, Post
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/community", tags=["community"])


def _client(x_client_id: str | None) -> str:
    if not x_client_id or len(x_client_id) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Client-Id header is required",
        )
    return x_client_id


def _author(name: str | None) -> str:
    if not name:
        return "익명"
    cleaned = name.strip()[:64]
    return cleaned or "익명"


# ---- Schemas --------------------------------------------------------------

class PostCreate(CamelModel):
    title: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=20000)
    author_name: str | None = Field(default=None, max_length=64)
    vulnerability_id: UUID | None = None


class PostUpdate(CamelModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    content: str | None = Field(default=None, min_length=1, max_length=20000)


class PostOut(CamelModel):
    id: int
    title: str
    content: str
    author_name: str
    vulnerability_id: UUID | None
    view_count: int
    comment_count: int
    is_owner: bool
    created_at: datetime
    updated_at: datetime


class PostListResponse(CamelModel):
    items: list[PostOut]
    total: int
    page: int
    page_size: int


class CommentCreate(CamelModel):
    content: str = Field(min_length=1, max_length=4000)
    author_name: str | None = Field(default=None, max_length=64)
    post_id: int | None = None
    vulnerability_id: UUID | None = None
    parent_id: int | None = None


class CommentOut(CamelModel):
    id: int
    content: str
    author_name: str
    post_id: int | None
    vulnerability_id: UUID | None
    parent_id: int | None
    is_owner: bool
    created_at: datetime


class CommentListResponse(CamelModel):
    items: list[CommentOut]
    total: int


# ---- Posts ---------------------------------------------------------------

@router.get("/posts", response_model=PostListResponse, response_model_by_alias=True)
async def list_posts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    vulnerability_id: UUID | None = Query(default=None, alias="vulnerabilityId"),
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    db: AsyncSession = Depends(get_db),
) -> PostListResponse:
    base = select(Post)
    count_base = select(func.count(Post.id))
    if vulnerability_id is not None:
        base = base.where(Post.vulnerability_id == vulnerability_id)
        count_base = count_base.where(Post.vulnerability_id == vulnerability_id)

    total = (await db.execute(count_base)).scalar_one()
    rows = (
        await db.execute(
            base.order_by(desc(Post.created_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    if rows:
        counts_stmt = (
            select(Comment.post_id, func.count(Comment.id))
            .where(Comment.post_id.in_([r.id for r in rows]))
            .group_by(Comment.post_id)
        )
        comment_counts = dict((await db.execute(counts_stmt)).all())
    else:
        comment_counts = {}

    items = [
        PostOut(
            id=r.id,
            title=r.title,
            content=r.content,
            author_name=r.author_name,
            vulnerability_id=r.vulnerability_id,
            view_count=r.view_count,
            comment_count=comment_counts.get(r.id, 0),
            is_owner=bool(x_client_id and r.client_id == x_client_id),
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]
    return PostListResponse(items=items, total=total, page=page, page_size=page_size)


@router.post(
    "/posts",
    response_model=PostOut,
    response_model_by_alias=True,
    status_code=201,
)
async def create_post(
    body: PostCreate,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    db: AsyncSession = Depends(get_db),
) -> PostOut:
    cid = _client(x_client_id)
    post = Post(
        client_id=cid,
        author_name=_author(body.author_name),
        title=body.title,
        content=body.content,
        vulnerability_id=body.vulnerability_id,
    )
    db.add(post)
    await db.commit()
    await db.refresh(post)
    return PostOut(
        id=post.id,
        title=post.title,
        content=post.content,
        author_name=post.author_name,
        vulnerability_id=post.vulnerability_id,
        view_count=post.view_count,
        comment_count=0,
        is_owner=True,
        created_at=post.created_at,
        updated_at=post.updated_at,
    )


@router.get("/posts/{post_id}", response_model=PostOut, response_model_by_alias=True)
async def get_post(
    post_id: int,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    db: AsyncSession = Depends(get_db),
) -> PostOut:
    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="post not found")

    post.view_count = (post.view_count or 0) + 1
    await db.commit()

    cnt = (
        await db.execute(select(func.count(Comment.id)).where(Comment.post_id == post.id))
    ).scalar_one()

    return PostOut(
        id=post.id,
        title=post.title,
        content=post.content,
        author_name=post.author_name,
        vulnerability_id=post.vulnerability_id,
        view_count=post.view_count,
        comment_count=cnt,
        is_owner=bool(x_client_id and post.client_id == x_client_id),
        created_at=post.created_at,
        updated_at=post.updated_at,
    )


@router.patch("/posts/{post_id}", response_model=PostOut, response_model_by_alias=True)
async def update_post(
    post_id: int,
    body: PostUpdate,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    db: AsyncSession = Depends(get_db),
) -> PostOut:
    cid = _client(x_client_id)
    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="post not found")
    if post.client_id != cid:
        raise HTTPException(status_code=403, detail="not the author")

    if body.title is not None:
        post.title = body.title
    if body.content is not None:
        post.content = body.content
    await db.commit()
    await db.refresh(post)

    cnt = (
        await db.execute(select(func.count(Comment.id)).where(Comment.post_id == post.id))
    ).scalar_one()
    return PostOut(
        id=post.id,
        title=post.title,
        content=post.content,
        author_name=post.author_name,
        vulnerability_id=post.vulnerability_id,
        view_count=post.view_count,
        comment_count=cnt,
        is_owner=True,
        created_at=post.created_at,
        updated_at=post.updated_at,
    )


@router.delete("/posts/{post_id}", status_code=204)
async def delete_post(
    post_id: int,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    db: AsyncSession = Depends(get_db),
) -> None:
    cid = _client(x_client_id)
    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="post not found")
    if post.client_id != cid:
        raise HTTPException(status_code=403, detail="not the author")
    await db.delete(post)
    await db.commit()


# ---- Comments ------------------------------------------------------------

@router.get("/comments", response_model=CommentListResponse, response_model_by_alias=True)
async def list_comments(
    post_id: int | None = Query(default=None, alias="postId"),
    vulnerability_id: UUID | None = Query(default=None, alias="vulnerabilityId"),
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    db: AsyncSession = Depends(get_db),
) -> CommentListResponse:
    if post_id is None and vulnerability_id is None:
        raise HTTPException(
            status_code=400, detail="postId or vulnerabilityId is required"
        )
    stmt = select(Comment)
    if post_id is not None:
        stmt = stmt.where(Comment.post_id == post_id)
    if vulnerability_id is not None:
        stmt = stmt.where(Comment.vulnerability_id == vulnerability_id)
    stmt = stmt.order_by(Comment.created_at.asc())

    rows = (await db.execute(stmt)).scalars().all()
    items = [
        CommentOut(
            id=c.id,
            content=c.content,
            author_name=c.author_name,
            post_id=c.post_id,
            vulnerability_id=c.vulnerability_id,
            parent_id=c.parent_id,
            is_owner=bool(x_client_id and c.client_id == x_client_id),
            created_at=c.created_at,
        )
        for c in rows
    ]
    return CommentListResponse(items=items, total=len(items))


@router.post(
    "/comments",
    response_model=CommentOut,
    response_model_by_alias=True,
    status_code=201,
)
async def create_comment(
    body: CommentCreate,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    db: AsyncSession = Depends(get_db),
) -> CommentOut:
    cid = _client(x_client_id)
    if body.post_id is None and body.vulnerability_id is None:
        raise HTTPException(status_code=400, detail="postId or vulnerabilityId is required")

    comment = Comment(
        client_id=cid,
        author_name=_author(body.author_name),
        content=body.content,
        post_id=body.post_id,
        vulnerability_id=body.vulnerability_id,
        parent_id=body.parent_id,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)
    return CommentOut(
        id=comment.id,
        content=comment.content,
        author_name=comment.author_name,
        post_id=comment.post_id,
        vulnerability_id=comment.vulnerability_id,
        parent_id=comment.parent_id,
        is_owner=True,
        created_at=comment.created_at,
    )


@router.delete("/comments/{comment_id}", status_code=204)
async def delete_comment(
    comment_id: int,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    db: AsyncSession = Depends(get_db),
) -> None:
    cid = _client(x_client_id)
    comment = (
        await db.execute(select(Comment).where(Comment.id == comment_id))
    ).scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="comment not found")
    if comment.client_id != cid:
        raise HTTPException(status_code=403, detail="not the author")
    await db.delete(comment)
    await db.commit()
