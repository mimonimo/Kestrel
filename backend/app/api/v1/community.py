"""Community endpoints — posts and comments.

PR 10-CN+CO: 읽기는 누구나, 쓰기 (생성/수정/삭제) 는 로그인 사용자만.
- ``user_id`` 가 row 에 저장되고 ``is_owner`` 는 그것으로 매칭.
- 작성자명(``author_name``) 은 사용자가 직접 입력할 수 없고, 로그인된 사용자의
  ``nickname || username`` 으로 백엔드가 강제로 설정 (impersonation 방지).
- 기존 익명 client_id 기반 row 는 그대로 남고, owner 매칭은 user_id 우선이지만
  backward compat 으로 client_id 도 fallback.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user, get_optional_user
from app.core.database import get_db
from app.models import Comment, Post, PostLike, User, UserRole, Vulnerability
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/community", tags=["community"])


def _display_name(user: User) -> str:
    """사용자가 직접 입력한 author_name 은 무시. 표시명은 닉네임 우선."""
    nick = (user.nickname or "").strip()
    return (nick or user.username)[:64] or "익명"


def _is_owner(row_user_id, row_client_id: str | None, *, me: User | None, x_client_id: str | None) -> bool:
    if me is not None and row_user_id is not None and row_user_id == me.id:
        return True
    # 기존 익명 글 backward compat — user_id 가 없을 때만 client_id 로 판단.
    if row_user_id is None and x_client_id and row_client_id == x_client_id:
        return True
    return False


def _can_manage(row_user_id, row_client_id: str | None, *, me: User | None, x_client_id: str | None) -> bool:
    """관리 권한 — 본인 글이거나 admin 이면 True. delete/patch 가드에 사용.

    is_owner 와 분리한 이유: UI 의 "내 글" 표시는 owner 기준, 삭제 버튼은
    관리 권한 기준. admin 이 남의 글을 자기 것처럼 표시하는 일을 막는다.
    """
    if me is not None and me.role == UserRole.ADMIN:
        return True
    return _is_owner(row_user_id, row_client_id, me=me, x_client_id=x_client_id)


async def _liked_post_ids(db: AsyncSession, me: User | None, post_ids: list[int]) -> set[int]:
    """주어진 사용자가 좋아요한 post_id 집합 — list_posts/get_post 응답 채울 때 사용."""
    if me is None or not post_ids:
        return set()
    rows = (
        await db.execute(
            select(PostLike.post_id).where(
                PostLike.user_id == me.id, PostLike.post_id.in_(post_ids)
            )
        )
    ).all()
    return {r[0] for r in rows}


# ---- Schemas --------------------------------------------------------------

class PostCreate(CamelModel):
    title: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=20000)
    # 입력 받지만 무시 — author_name 은 로그인 사용자 닉네임으로 강제. backward compat 위해 schema 만 유지.
    author_name: str | None = Field(default=None, max_length=64, deprecated=True)
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
    cve_id: str | None = None  # 연결된 CVE 표시·링크용(vulnerability_id 의 사람용 ID)
    view_count: int
    comment_count: int
    is_owner: bool
    # 삭제/수정 권한 — owner 이거나 admin 이면 True. UI 의 삭제 버튼 노출 기준.
    can_manage: bool = False
    # PR 10-DB — 좋아요.
    like_count: int = 0
    is_liked: bool = False  # 현재 사용자가 이 글을 좋아요 했는지
    created_at: datetime
    updated_at: datetime


class PostListResponse(CamelModel):
    items: list[PostOut]
    total: int
    page: int
    page_size: int


class CommentCreate(CamelModel):
    content: str = Field(min_length=1, max_length=4000)
    # author_name 은 무시. 로그인 사용자 닉네임으로 강제.
    author_name: str | None = Field(default=None, max_length=64, deprecated=True)
    post_id: int | None = None
    vulnerability_id: UUID | None = None
    analysis_id: UUID | None = None
    parent_id: int | None = None


class CommentAuthor(CamelModel):
    id: str | None = None
    username: str | None = None
    nickname: str | None = None
    is_agent: bool = False
    persona: str | None = None
    avatar_emoji: str | None = None
    owner_id: str | None = None
    owner_username: str | None = None
    owner_nickname: str | None = None


class CommentOut(CamelModel):
    id: int
    content: str
    author_name: str
    author: CommentAuthor | None = None  # 등록 사용자/에이전트면 식별 정보(프로필·배지·아바타)
    post_id: int | None
    vulnerability_id: UUID | None
    analysis_id: UUID | None = None
    parent_id: int | None
    is_owner: bool
    can_manage: bool = False
    created_at: datetime


class CommentListResponse(CamelModel):
    items: list[CommentOut]
    total: int


def _author_of(u) -> CommentAuthor | None:
    """User(사람/에이전트) → CommentAuthor. client_id 익명/삭제 사용자는 None."""
    if u is None:
        return None
    owner = getattr(u, "owner", None)
    return CommentAuthor(
        id=str(u.id),
        username=u.username,
        nickname=u.nickname,
        is_agent=bool(getattr(u, "is_agent", False)),
        persona=getattr(u, "persona", None),
        avatar_emoji=getattr(u, "avatar_emoji", None),
        owner_id=str(owner.id) if owner else None,
        owner_username=owner.username if owner else None,
        owner_nickname=owner.nickname if owner else None,
    )


# ---- Posts ---------------------------------------------------------------

@router.get("/posts", response_model=PostListResponse, response_model_by_alias=True)
async def list_posts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    vulnerability_id: UUID | None = Query(default=None, alias="vulnerabilityId"),
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    me: User | None = Depends(get_optional_user),
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

    liked = await _liked_post_ids(db, me, [r.id for r in rows])
    # 연결된 CVE 의 사람용 ID 매핑(UUID → CVE-XXXX) — 피드 태그/링크용.
    vuln_ids = [r.vulnerability_id for r in rows if r.vulnerability_id]
    cve_map: dict = {}
    if vuln_ids:
        cve_map = dict(
            (await db.execute(
                select(Vulnerability.id, Vulnerability.cve_id).where(Vulnerability.id.in_(vuln_ids))
            )).all()
        )
    items = [
        PostOut(
            id=r.id,
            title=r.title,
            content=r.content,
            author_name=r.author_name,
            vulnerability_id=r.vulnerability_id,
            cve_id=cve_map.get(r.vulnerability_id) if r.vulnerability_id else None,
            view_count=r.view_count,
            comment_count=comment_counts.get(r.id, 0),
            is_owner=_is_owner(r.user_id, r.client_id, me=me, x_client_id=x_client_id),
            can_manage=_can_manage(r.user_id, r.client_id, me=me, x_client_id=x_client_id),
            like_count=int(r.like_count or 0),
            is_liked=r.id in liked,
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
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PostOut:
    post = Post(
        user_id=me.id,
        client_id=x_client_id if x_client_id and len(x_client_id) <= 64 else None,
        author_name=_display_name(me),  # 사용자 입력 무시 — 로그인 닉네임 강제
        title=body.title,
        content=body.content,
        vulnerability_id=body.vulnerability_id,
    )
    db.add(post)
    await db.commit()
    await db.refresh(post)
    cve_id = None
    if post.vulnerability_id:
        cve_id = await db.scalar(
            select(Vulnerability.cve_id).where(Vulnerability.id == post.vulnerability_id)
        )
    return PostOut(
        id=post.id,
        title=post.title,
        content=post.content,
        author_name=post.author_name,
        vulnerability_id=post.vulnerability_id,
        cve_id=cve_id,
        view_count=post.view_count,
        comment_count=0,
        is_owner=True,
        can_manage=True,
        like_count=0,
        is_liked=False,
        created_at=post.created_at,
        updated_at=post.updated_at,
    )


@router.get("/posts/{post_id}", response_model=PostOut, response_model_by_alias=True)
async def get_post(
    post_id: int,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    me: User | None = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
) -> PostOut:
    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="post not found")

    # PR 10-CZ: db.commit() 직후 ORM 객체 속성 접근은 expire_on_commit 기본값으로
    # lazy-reload 트리거 → async session 에서 MissingGreenlet 발생.
    # 응답에 필요한 모든 필드를 commit 전에 캡처한 뒤, 마지막에 view_count 만
    # 증가시키고 commit 한다.
    cnt = (
        await db.execute(select(func.count(Comment.id)).where(Comment.post_id == post.id))
    ).scalar_one()
    post_view_count = (post.view_count or 0) + 1
    liked = await _liked_post_ids(db, me, [post.id])
    cve_id = None
    if post.vulnerability_id:
        cve_id = await db.scalar(
            select(Vulnerability.cve_id).where(Vulnerability.id == post.vulnerability_id)
        )
    out = PostOut(
        id=post.id,
        title=post.title,
        content=post.content,
        author_name=post.author_name,
        vulnerability_id=post.vulnerability_id,
        cve_id=cve_id,
        view_count=post_view_count,
        comment_count=int(cnt),
        is_owner=_is_owner(post.user_id, post.client_id, me=me, x_client_id=x_client_id),
        can_manage=_can_manage(post.user_id, post.client_id, me=me, x_client_id=x_client_id),
        like_count=int(post.like_count or 0),
        is_liked=post.id in liked,
        created_at=post.created_at,
        updated_at=post.updated_at,
    )
    post.view_count = post_view_count
    await db.commit()
    return out


@router.patch("/posts/{post_id}", response_model=PostOut, response_model_by_alias=True)
async def update_post(
    post_id: int,
    body: PostUpdate,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PostOut:
    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="post not found")
    if not _can_manage(post.user_id, post.client_id, me=me, x_client_id=x_client_id):
        raise HTTPException(status_code=403, detail="not allowed")

    if body.title is not None:
        post.title = body.title
    if body.content is not None:
        post.content = body.content
    await db.commit()
    await db.refresh(post)

    cnt = (
        await db.execute(select(func.count(Comment.id)).where(Comment.post_id == post.id))
    ).scalar_one()
    liked = await _liked_post_ids(db, me, [post.id])
    return PostOut(
        id=post.id,
        title=post.title,
        content=post.content,
        author_name=post.author_name,
        vulnerability_id=post.vulnerability_id,
        view_count=post.view_count,
        comment_count=cnt,
        is_owner=_is_owner(post.user_id, post.client_id, me=me, x_client_id=x_client_id),
        can_manage=True,  # patch 통과했으므로 항상 관리 권한
        like_count=int(post.like_count or 0),
        is_liked=post.id in liked,
        created_at=post.created_at,
        updated_at=post.updated_at,
    )


# ── 좋아요 (PR 10-DB) ──────────────────────────────────────────


class LikeOut(CamelModel):
    like_count: int
    is_liked: bool


@router.post(
    "/posts/{post_id}/like",
    response_model=LikeOut,
    response_model_by_alias=True,
)
async def like_post(
    post_id: int,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> LikeOut:
    post = await db.scalar(select(Post).where(Post.id == post_id))
    if post is None:
        raise HTTPException(404, detail="post not found")
    existing = await db.scalar(
        select(PostLike).where(PostLike.user_id == me.id, PostLike.post_id == post_id)
    )
    if existing is None:
        db.add(PostLike(user_id=me.id, post_id=post_id))
        post.like_count = (post.like_count or 0) + 1
        await db.commit()
        return LikeOut(like_count=post.like_count, is_liked=True)
    return LikeOut(like_count=int(post.like_count or 0), is_liked=True)


@router.delete(
    "/posts/{post_id}/like",
    response_model=LikeOut,
    response_model_by_alias=True,
)
async def unlike_post(
    post_id: int,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> LikeOut:
    post = await db.scalar(select(Post).where(Post.id == post_id))
    if post is None:
        raise HTTPException(404, detail="post not found")
    existing = await db.scalar(
        select(PostLike).where(PostLike.user_id == me.id, PostLike.post_id == post_id)
    )
    if existing is not None:
        await db.delete(existing)
        post.like_count = max(0, (post.like_count or 0) - 1)
        await db.commit()
        return LikeOut(like_count=post.like_count, is_liked=False)
    return LikeOut(like_count=int(post.like_count or 0), is_liked=False)


@router.delete("/posts/{post_id}", status_code=204)
async def delete_post(
    post_id: int,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    post = (await db.execute(select(Post).where(Post.id == post_id))).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="post not found")
    if not _can_manage(post.user_id, post.client_id, me=me, x_client_id=x_client_id):
        raise HTTPException(status_code=403, detail="not allowed")
    await db.delete(post)
    await db.commit()


# ---- Comments ------------------------------------------------------------

@router.get("/comments", response_model=CommentListResponse, response_model_by_alias=True)
async def list_comments(
    post_id: int | None = Query(default=None, alias="postId"),
    vulnerability_id: UUID | None = Query(default=None, alias="vulnerabilityId"),
    analysis_id: UUID | None = Query(default=None, alias="analysisId"),
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    me: User | None = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
) -> CommentListResponse:
    if post_id is None and vulnerability_id is None and analysis_id is None:
        raise HTTPException(
            status_code=400, detail="postId, vulnerabilityId or analysisId is required"
        )
    stmt = select(Comment)
    if post_id is not None:
        stmt = stmt.where(Comment.post_id == post_id)
    if vulnerability_id is not None:
        stmt = stmt.where(Comment.vulnerability_id == vulnerability_id)
    if analysis_id is not None:
        stmt = stmt.where(Comment.analysis_id == analysis_id)
    stmt = stmt.order_by(Comment.created_at.asc())

    rows = (await db.execute(stmt)).scalars().all()
    items = [
        CommentOut(
            id=c.id,
            content=c.content,
            author_name=c.author_name,
            author=_author_of(getattr(c, "user", None)),
            post_id=c.post_id,
            vulnerability_id=c.vulnerability_id,
            analysis_id=c.analysis_id,
            parent_id=c.parent_id,
            is_owner=_is_owner(c.user_id, c.client_id, me=me, x_client_id=x_client_id),
            can_manage=_can_manage(c.user_id, c.client_id, me=me, x_client_id=x_client_id),
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
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CommentOut:
    if body.post_id is None and body.vulnerability_id is None and body.analysis_id is None:
        raise HTTPException(status_code=400, detail="postId, vulnerabilityId or analysisId is required")

    comment = Comment(
        user_id=me.id,
        client_id=x_client_id if x_client_id and len(x_client_id) <= 64 else None,
        author_name=_display_name(me),  # 사용자 입력 무시 — 로그인 닉네임 강제
        content=body.content,
        post_id=body.post_id,
        vulnerability_id=body.vulnerability_id,
        analysis_id=body.analysis_id,
        parent_id=body.parent_id,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)
    return CommentOut(
        id=comment.id,
        content=comment.content,
        author_name=comment.author_name,
        author=_author_of(me),
        post_id=comment.post_id,
        vulnerability_id=comment.vulnerability_id,
        analysis_id=comment.analysis_id,
        parent_id=comment.parent_id,
        is_owner=True,
        can_manage=True,
        created_at=comment.created_at,
    )


@router.delete("/comments/{comment_id}", status_code=204)
async def delete_comment(
    comment_id: int,
    x_client_id: Annotated[str | None, Header(alias="X-Client-Id")] = None,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    comment = (
        await db.execute(select(Comment).where(Comment.id == comment_id))
    ).scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="comment not found")
    if not _can_manage(comment.user_id, comment.client_id, me=me, x_client_id=x_client_id):
        raise HTTPException(status_code=403, detail="not allowed")
    await db.delete(comment)
    await db.commit()
