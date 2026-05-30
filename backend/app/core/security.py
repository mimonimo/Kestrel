"""Password hashing + JWT 발급/검증.

토큰 유출 방지 원칙:
- JWT secret 은 환경변수 ``JWT_SECRET`` 에서만 로드. 코드 하드코딩 절대 금지.
- 비밀번호는 bcrypt (cost 12) 해싱 — 응답에는 password_hash 직렬화하지 않음.
- 로그/Sentry/structlog 에 토큰·비번 절대 기록 X.
- 토큰은 HttpOnly + Secure + SameSite=Strict 쿠키로만 전달 (auth 라우터).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

# JWT 알고리즘 — HS256 (대칭키, 단일 서버).
# 멀티 서버/Lambda 분리 시 RS256 (비대칭) 로 전환 권장.
_ALG = "HS256"

# 액세스 토큰 만료 — 짧게 잡고 재발급으로 회전.
ACCESS_TOKEN_TTL = timedelta(hours=12)


def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd.verify(plain, hashed)
    except Exception:  # noqa: BLE001 — bcrypt 가 던지는 모든 예외를 false 로 흡수
        return False


def issue_access_token(*, user_id: str, role: str, extra: dict[str, Any] | None = None) -> str:
    """sub=user_id, role=..., exp=now+TTL. 추가 클레임은 extra 로."""
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + ACCESS_TOKEN_TTL).timestamp()),
    }
    if extra:
        claims.update(extra)
    return jwt.encode(claims, get_settings().jwt_secret, algorithm=_ALG)


def decode_access_token(token: str) -> dict[str, Any] | None:
    """유효하면 claims dict, 만료/위조면 None. 예외는 호출 측에서 보지 못하게."""
    try:
        return jwt.decode(token, get_settings().jwt_secret, algorithms=[_ALG])
    except JWTError:
        return None


# Admin 자동 부여 — 환경변수 INITIAL_ADMIN_EMAILS 의 콤마 분리 리스트.
# 가입 시 email 매칭되면 role=ADMIN 으로 생성.
def is_admin_email(email: str) -> bool:
    raw = get_settings().initial_admin_emails or ""
    allowed = {e.strip().lower() for e in raw.split(",") if e.strip()}
    return email.strip().lower() in allowed
