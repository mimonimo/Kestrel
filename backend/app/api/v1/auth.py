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

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import EmailStr, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import COOKIE_NAME, get_current_user
from app.core.audit import AuditAction, record_audit
from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import (
    enforce_login_rate_limit,
    enforce_signup_rate_limit,
    record_login_failure,
    reset_login_failures,
)
from app.core.request_ip import client_ip
from app.core.security import (
    ACCESS_TOKEN_TTL,
    DUMMY_PASSWORD_HASH,
    hash_password,
    is_admin_email,
    issue_access_token,
    verify_password,
)
from app.models import LoginLog, User, UserRole
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


class ChangePasswordIn(CamelModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


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
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> MeOut:
    # 대량 계정 생성/스팸 억제 — IP 기준 시도 제한.
    await enforce_signup_rate_limit(client_ip(request) or "unknown")

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
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email_norm,
        username=body.username,
        password_hash=hash_password(body.password),
        role=role,
        last_login_at=now,
    )
    db.add(user)
    # 가입은 곧 첫 로그인(세션 시작) — 접속 로그에도 남긴다 (PR 10-EP).
    ip = client_ip(request)
    ua = (request.headers.get("user-agent") or "")[:512] or None
    db.add(LoginLog(user_id=user.id, ip=ip, user_agent=ua))
    await db.commit()

    await record_audit(
        db, action=AuditAction.SIGNUP, actor=user, request=request,
        detail=f"role={role.value}",
    )

    token = issue_access_token(user_id=str(user.id), role=role.value)
    _set_auth_cookie(response, token)
    return _to_me(user)


@router.post("/login", response_model=MeOut, response_model_by_alias=True)
async def login(
    body: LoginIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> MeOut:
    email_norm = body.email.strip().lower()
    ip = client_ip(request) or "unknown"

    # 브루트포스 방어 — 최근 실패 누적이 임계치를 넘으면 검증 전에 429.
    await enforce_login_rate_limit(ip, email_norm)

    user = await db.scalar(select(User).where(User.email == email_norm))
    # 사용자 열거(timing) 방어 — 없는 이메일이어도 bcrypt 1회 동등 수행.
    if user is None:
        verify_password(body.password, DUMMY_PASSWORD_HASH)
        valid = False
    else:
        valid = verify_password(body.password, user.password_hash)

    if not valid:
        await record_login_failure(ip, email_norm)
        await record_audit(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor=user,
            actor_label=email_norm,
            request=request,
            detail="존재하지 않는 계정" if user is None else "비밀번호 불일치",
        )
        # 동일 메시지 — 이메일 존재 여부 노출 방지.
        raise HTTPException(401, detail="이메일 또는 비밀번호가 일치하지 않습니다.")

    # 성공 — 실패 카운터 초기화(정상 사용자 잠김 방지).
    await reset_login_failures(ip, email_norm)

    # PR 10-DE — last_login_at + login_logs 갱신. 운영자 추적용.
    # PR 10-DM — Caddy 뒤라 request.client.host 는 항상 bridge IP 만 잡혀서
    # 실제 IP 가 X-Forwarded-For 에 있다. client_ip() 가 leftmost 추출.
    user.last_login_at = datetime.now(timezone.utc)
    ua = (request.headers.get("user-agent") or "")[:512] or None
    db.add(LoginLog(user_id=user.id, ip=ip if ip != "unknown" else None, user_agent=ua))
    await db.commit()

    await record_audit(db, action=AuditAction.LOGIN_SUCCESS, actor=user, request=request)

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


@router.post("/change-password", status_code=204)
async def change_password(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """로그인 사용자 비밀번호 변경 — 현재 비밀번호 재확인 필수.

    변경 성공 시 새 토큰을 재발급해 현재 세션은 유지하되, 다른 기기/세션은
    토큰 TTL(12h) 만료 후 자연 무효화된다. (서버측 즉시 폐기는 향후 jti 도입 시.)
    """
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, detail="현재 비밀번호가 일치하지 않습니다.")
    if body.new_password == body.current_password:
        raise HTTPException(400, detail="새 비밀번호가 현재 비밀번호와 같습니다.")

    user.password_hash = hash_password(body.new_password)
    await db.commit()

    await record_audit(db, action=AuditAction.PASSWORD_CHANGE, actor=user, request=request)

    # 비밀번호가 바뀌었으니 현재 쿠키 토큰을 새로 발급해 갱신.
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    token = issue_access_token(user_id=str(user.id), role=role)
    _set_auth_cookie(response, token)
