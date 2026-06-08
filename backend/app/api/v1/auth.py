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
from app.core.auth_tokens import (
    PURPOSE_EMAIL_VERIFY,
    PURPOSE_PASSWORD_RESET,
    consume_token,
    create_token,
    peek_token,
)
from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import (
    enforce_email_send_rate_limit,
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
from app.services.email import send_password_reset_email, send_verification_email

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


class SignupOut(CamelModel):
    """가입 직후 응답 — 인증 메일을 보냈으니 로그인 전 인증을 요구."""
    email: str
    email_verification_required: bool = True
    message: str


class EmailIn(CamelModel):
    email: EmailStr


class VerifyEmailIn(CamelModel):
    token: str = Field(min_length=8, max_length=512)


class ResetPasswordIn(CamelModel):
    token: str = Field(min_length=8, max_length=512)
    new_password: str = Field(min_length=8, max_length=128)


class SimpleMessageOut(CamelModel):
    message: str


class ValidateResetOut(CamelModel):
    valid: bool


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


async def _send_verification(db: AsyncSession, user: User, request: Request) -> None:
    """인증 토큰 발급 + 메일 발송 + 감사 기록. 발송 실패는 호출자에게 전파."""
    settings = get_settings()
    token = await create_token(
        PURPOSE_EMAIL_VERIFY, user.id, settings.email_verify_token_ttl_hours * 3600
    )
    await send_verification_email(user.email, token)
    await record_audit(
        db, action=AuditAction.EMAIL_VERIFY_SENT, actor=user, request=request
    )


# ─── 라우트 ────────────────────────────────────────────
@router.post("/signup", response_model=SignupOut, response_model_by_alias=True, status_code=201)
async def signup(
    body: SignupIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> SignupOut:
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
    # 가입 시점엔 미인증 상태로 생성 — 메일 링크 검증 전까지 로그인 차단.
    # 세션을 시작하지 않으므로 last_login_at / LoginLog 는 기록하지 않는다.
    user = User(
        id=uuid.uuid4(),
        email=email_norm,
        username=body.username,
        password_hash=hash_password(body.password),
        role=role,
        email_verified=False,
    )
    db.add(user)
    await db.commit()

    await record_audit(
        db, action=AuditAction.SIGNUP, actor=user, request=request,
        detail=f"role={role.value}",
    )

    # 인증 메일 발송 — 실패해도 계정은 생성됐으니 재발송으로 복구 가능.
    try:
        await _send_verification(db, user, request)
    except Exception:  # noqa: BLE001 — 발송 실패가 가입 자체를 롤백하지 않음
        pass

    return SignupOut(
        email=email_norm,
        message="인증 메일을 보냈습니다. 메일의 링크를 눌러 인증을 완료해 주세요.",
    )


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

    # 이메일 인증 전 로그인 차단 — 프론트가 재발송 UI 를 띄울 수 있게 구조화 detail.
    if not user.email_verified:
        await record_audit(
            db, action=AuditAction.LOGIN_FAILURE, actor=user, request=request,
            detail="이메일 미인증",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "email_not_verified",
                "message": "이메일 인증이 필요합니다. 메일의 인증 링크를 확인해 주세요.",
            },
        )

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


# ─── 이메일 인증 ──────────────────────────────────────────
@router.post("/verify-email", response_model=MeOut, response_model_by_alias=True)
async def verify_email(
    body: VerifyEmailIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> MeOut:
    """메일 링크의 토큰으로 이메일 인증을 완료하고 곧바로 로그인 세션을 발급한다."""
    user_id = await consume_token(PURPOSE_EMAIL_VERIFY, body.token)
    if user_id is None:
        raise HTTPException(
            400, detail="유효하지 않거나 만료된 링크입니다. 인증 메일을 다시 요청해 주세요."
        )
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(400, detail="유효하지 않은 링크입니다.")

    if not user.email_verified:
        user.email_verified = True
        user.email_verified_at = datetime.now(timezone.utc)
        user.last_login_at = datetime.now(timezone.utc)
        db.add(LoginLog(
            user_id=user.id,
            ip=(client_ip(request) or None),
            user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        ))
        await db.commit()
        await record_audit(
            db, action=AuditAction.EMAIL_VERIFIED, actor=user, request=request
        )

    # 인증 완료 → 바로 로그인 상태로 진입(세션 쿠키 발급).
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    token = issue_access_token(user_id=str(user.id), role=role)
    _set_auth_cookie(response, token)
    return _to_me(user)


@router.post("/resend-verification", response_model=SimpleMessageOut, response_model_by_alias=True)
async def resend_verification(
    body: EmailIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> SimpleMessageOut:
    """인증 메일 재발송. 계정 존재/인증 여부를 노출하지 않도록 항상 동일 응답."""
    email_norm = body.email.strip().lower()
    await enforce_email_send_rate_limit(client_ip(request) or "unknown", email_norm)

    user = await db.scalar(select(User).where(User.email == email_norm))
    if user is not None and not user.email_verified:
        try:
            await _send_verification(db, user, request)
        except Exception:  # noqa: BLE001 — 발송 실패해도 응답은 동일
            pass

    return SimpleMessageOut(
        message="해당 이메일로 가입된 미인증 계정이 있으면 인증 메일을 다시 보냈습니다."
    )


# ─── 비밀번호 재설정 ──────────────────────────────────────
@router.post("/forgot-password", response_model=SimpleMessageOut, response_model_by_alias=True)
async def forgot_password(
    body: EmailIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> SimpleMessageOut:
    """재설정 메일 발송. 이메일 존재 여부를 노출하지 않도록 항상 200 + 동일 메시지."""
    email_norm = body.email.strip().lower()
    await enforce_email_send_rate_limit(client_ip(request) or "unknown", email_norm)

    user = await db.scalar(select(User).where(User.email == email_norm))
    if user is not None:
        settings = get_settings()
        try:
            token = await create_token(
                PURPOSE_PASSWORD_RESET, user.id,
                settings.password_reset_token_ttl_minutes * 60,
            )
            await send_password_reset_email(user.email, token)
            await record_audit(
                db, action=AuditAction.PASSWORD_RESET_REQUEST, actor=user, request=request
            )
        except Exception:  # noqa: BLE001 — 발송 실패해도 응답은 동일
            pass

    return SimpleMessageOut(
        message="해당 이메일로 가입된 계정이 있으면 비밀번호 재설정 메일을 보냈습니다."
    )


@router.post("/reset-password", response_model=SimpleMessageOut, response_model_by_alias=True)
async def reset_password(
    body: ResetPasswordIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> SimpleMessageOut:
    """재설정 토큰으로 새 비밀번호 설정. 성공 시 기존 세션 쿠키는 제거."""
    user_id = await consume_token(PURPOSE_PASSWORD_RESET, body.token)
    if user_id is None:
        raise HTTPException(
            400, detail="유효하지 않거나 만료된 링크입니다. 비밀번호 찾기를 다시 요청해 주세요."
        )
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(400, detail="유효하지 않은 링크입니다.")

    user.password_hash = hash_password(body.new_password)
    # 비밀번호를 잊을 정도면 메일 인증은 사실상 통과 — 미인증이었다면 함께 인증 처리.
    if not user.email_verified:
        user.email_verified = True
        user.email_verified_at = datetime.now(timezone.utc)
    await db.commit()

    await record_audit(db, action=AuditAction.PASSWORD_RESET, actor=user, request=request)

    # 안전을 위해 현재 브라우저의 세션 쿠키 제거 → 새 비밀번호로 다시 로그인 유도.
    _clear_auth_cookie(response)
    return SimpleMessageOut(message="비밀번호가 변경되었습니다. 새 비밀번호로 로그인해 주세요.")


@router.get(
    "/reset-password/validate",
    response_model=ValidateResetOut,
    response_model_by_alias=True,
)
async def validate_reset_token(token: str = "") -> ValidateResetOut:
    """재설정 링크 진입 시 토큰 유효성 사전 확인 — 토큰을 소비하지 않는다.
    만료/사용/무효 링크면 프론트가 폼 대신 안내 화면을 즉시 띄울 수 있게."""
    uid = await peek_token(PURPOSE_PASSWORD_RESET, token)
    return ValidateResetOut(valid=uid is not None)
