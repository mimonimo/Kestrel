"""Auth — signup / login / logout / me.

쿠키 발급 정책 (운영):
- HttpOnly  : JS 에서 접근 불가 → XSS 토큰 탈취 방지
- Secure    : HTTPS 에서만 전송 (env=prod 일 때)
- SameSite=Lax : 외부 사이트의 CSRF 차단 (Strict 가 더 안전하지만 OAuth redirect 호환성)
- Path=/    : 전체 API 에 자동 첨부
- 만료      : ACCESS_TOKEN_TTL (12h) — 로그아웃은 쿠키 삭제
"""
from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import EmailStr, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import COOKIE_NAME, get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    ACCESS_TOKEN_TTL,
    hash_password,
    is_admin_email,
    issue_access_token,
    verify_password,
)
from app.models import User, UserRole
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/auth", tags=["auth"])


# ─── 스키마 ────────────────────────────────────────────
class SignupIn(CamelModel):
    email: EmailStr
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(CamelModel):
    email: EmailStr
    password: str


class MeOut(CamelModel):
    id: str
    email: str
    username: str
    nickname: str | None = None
    role: str
    is_admin: bool


def _to_me(u: User) -> MeOut:
    return MeOut(
        id=str(u.id),
        email=u.email,
        username=u.username,
        nickname=u.nickname,
        role=u.role.value if hasattr(u.role, "value") else str(u.role),
        is_admin=u.role == UserRole.ADMIN,
    )


def _set_auth_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=int(ACCESS_TOKEN_TTL.total_seconds()),
        httponly=True,
        secure=settings.env == "production",
        samesite="lax",
        path="/",
    )


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(key=COOKIE_NAME, path="/")


_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_가-힣\-.]{2,64}$")


# ─── 라우트 ────────────────────────────────────────────
@router.post("/signup", response_model=MeOut, response_model_by_alias=True, status_code=201)
async def signup(
    body: SignupIn,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> MeOut:
    if not _USERNAME_RE.match(body.username):
        raise HTTPException(400, detail="사용자명은 한글·영문·숫자·_-. 만 가능합니다.")

    # 중복 체크 (대소문자 무시)
    email_norm = body.email.strip().lower()
    exists = await db.scalar(
        select(User).where(
            or_(User.email == email_norm, User.username == body.username)
        )
    )
    if exists is not None:
        raise HTTPException(409, detail="이미 사용 중인 이메일 또는 사용자명입니다.")

    role = UserRole.ADMIN if is_admin_email(email_norm) else UserRole.USER
    user = User(
        id=uuid.uuid4(),
        email=email_norm,
        username=body.username,
        password_hash=hash_password(body.password),
        role=role,
    )
    db.add(user)
    await db.commit()

    token = issue_access_token(user_id=str(user.id), role=role.value)
    _set_auth_cookie(response, token)
    return _to_me(user)


@router.post("/login", response_model=MeOut, response_model_by_alias=True)
async def login(
    body: LoginIn,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> MeOut:
    email_norm = body.email.strip().lower()
    user = await db.scalar(select(User).where(User.email == email_norm))
    if user is None or not verify_password(body.password, user.password_hash):
        # 동일 메시지 — 이메일 존재 여부 노출 방지.
        raise HTTPException(401, detail="이메일 또는 비밀번호가 일치하지 않습니다.")

    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    token = issue_access_token(user_id=str(user.id), role=role)
    _set_auth_cookie(response, token)
    return _to_me(user)


@router.post("/logout", status_code=204)
async def logout(response: Response) -> None:
    _clear_auth_cookie(response)


@router.get("/me", response_model=MeOut, response_model_by_alias=True)
async def me(user: User = Depends(get_current_user)) -> MeOut:
    return _to_me(user)
