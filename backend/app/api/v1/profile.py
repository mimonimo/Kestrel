"""사용자 프로필 — GET /me, PATCH /me/profile.

``GET /auth/me`` 와 분리한 이유: 프로필 편집/조회는 nickname/bio 같은
프레젠테이션 데이터, ``/auth/me`` 는 세션 신원 (id/email/role/isAdmin).
응답 모델에 password_hash 가 절대 포함되지 않도록 명시 직렬화만 사용.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/me", tags=["profile"])


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
