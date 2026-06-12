"""사용자 프로필 — GET /me, PATCH /me/profile.

``GET /auth/me`` 와 분리한 이유: 프로필 편집/조회는 nickname/bio 같은
프레젠테이션 데이터, ``/auth/me`` 는 세션 신원 (id/email/role/isAdmin).
응답 모델에 password_hash 가 절대 포함되지 않도록 명시 직렬화만 사용.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import AnalysisResult, User, UserRole
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/me", tags=["profile"])
users_router = APIRouter(prefix="/users", tags=["profile"])


class ProfileOut(CamelModel):
    id: str
    email: str
    username: str
    nickname: str | None
    bio: str | None
    role: str
    is_admin: bool


class ProfileUpdate(CamelModel):
    nickname: str | None = Field(default=None, max_length=64)
    bio: str | None = Field(default=None, max_length=2000)


_NICKNAME_RE = re.compile(r"^[a-zA-Z0-9_가-힣\- .]{2,64}$")


def _to_profile(u: User) -> ProfileOut:
    return ProfileOut(
        id=str(u.id),
        email=u.email,
        username=u.username,
        nickname=u.nickname,
        bio=u.bio,
        role=u.role.value if hasattr(u.role, "value") else str(u.role),
        is_admin=u.role == UserRole.ADMIN,
    )


@router.get("/profile", response_model=ProfileOut, response_model_by_alias=True)
async def get_profile(user: User = Depends(get_current_user)) -> ProfileOut:
    return _to_profile(user)


@router.patch("/profile", response_model=ProfileOut, response_model_by_alias=True)
async def update_profile(
    body: ProfileUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ProfileOut:
    if body.nickname is not None:
        nick = body.nickname.strip()
        if nick == "":
            user.nickname = None
        else:
            if not _NICKNAME_RE.match(nick):
                raise HTTPException(400, detail="닉네임은 2-64자, 한글·영문·숫자·공백·_-. 만 가능합니다.")
            user.nickname = nick
    if body.bio is not None:
        user.bio = body.bio.strip() or None

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return _to_profile(user)


# ─── 공개 사용자 프로필 (GitHub 프로필식) ─────────────────────
class PublicAnalysis(CamelModel):
    id: str
    cve_id: str
    title: str | None = None
    created_at: str | None = None


class PublicAgent(CamelModel):
    id: str
    name: str
    persona: str | None = None
    avatar_emoji: str | None = None
    analyses: int = 0


class PublicProfileOut(CamelModel):
    username: str
    nickname: str | None = None
    bio: str | None = None
    role: str
    is_admin: bool = False
    created_at: str | None = None
    analysis_count: int = 0
    agent_count: int = 0
    analyses: list[PublicAnalysis] = []
    agents: list[PublicAgent] = []


@users_router.get("/{username}", response_model=PublicProfileOut, response_model_by_alias=True)
async def public_profile(
    username: str,
    db: AsyncSession = Depends(get_db),
) -> PublicProfileOut:
    """공개 사용자 프로필 — 이름·소개·공유 분석·보유 에이전트. 인증 불필요."""
    u = await db.scalar(
        select(User).where(User.username == username, User.is_agent.is_(False))
    )
    if u is None:
        raise HTTPException(404, detail="사용자를 찾을 수 없습니다.")

    a_count = await db.scalar(
        select(func.count(AnalysisResult.id)).where(
            AnalysisResult.user_id == u.id, AnalysisResult.visibility == "public"
        )
    )
    arows = (
        await db.execute(
            select(AnalysisResult)
            .where(AnalysisResult.user_id == u.id, AnalysisResult.visibility == "public")
            .order_by(AnalysisResult.created_at.desc())
            .limit(30)
        )
    ).scalars().all()

    # 이 사용자가 소유한 에이전트
    agents = (
        await db.execute(
            select(User)
            .where(User.is_agent.is_(True), User.owner_user_id == u.id)
            .order_by(User.created_at.asc())
        )
    ).scalars().all()
    agent_counts: dict = {}
    if agents:
        aids = [a.id for a in agents]
        agent_counts = dict(
            (
                await db.execute(
                    select(AnalysisResult.user_id, func.count(AnalysisResult.id))
                    .where(AnalysisResult.user_id.in_(aids))
                    .group_by(AnalysisResult.user_id)
                )
            ).all()
        )

    return PublicProfileOut(
        username=u.username,
        nickname=u.nickname,
        bio=u.bio,
        role=u.role.value if hasattr(u.role, "value") else str(u.role),
        is_admin=u.role == UserRole.ADMIN,
        created_at=u.created_at.isoformat() if getattr(u, "created_at", None) else None,
        analysis_count=int(a_count or 0),
        agent_count=len(agents),
        analyses=[
            PublicAnalysis(
                id=str(r.id),
                cve_id=r.cve_id,
                title=r.title,
                created_at=r.created_at.isoformat() if r.created_at else None,
            )
            for r in arows
        ],
        agents=[
            PublicAgent(
                id=str(a.id),
                name=a.nickname or a.username,
                persona=a.persona,
                avatar_emoji=a.avatar_emoji or "🤖",
                analyses=int(agent_counts.get(a.id, 0)),
            )
            for a in agents
        ],
    )
