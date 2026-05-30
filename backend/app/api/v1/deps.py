"""인증 의존성 — get_current_user / get_optional_user / require_admin.

쿠키 ``access_token`` 에서 JWT 추출 후 검증. 토큰 없거나 위조면 401.
optional 버전은 None 을 반환해 비로그인 사용자도 같은 엔드포인트를 쓸 수 있게 함.
"""
from __future__ import annotations

import uuid

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models import User, UserRole

COOKIE_NAME = "access_token"


async def get_optional_user(
    access_token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """토큰이 유효하면 User, 없거나 위조면 None — 401 던지지 않음.

    파싱된 취약점/분석 결과 조회처럼 익명 OK 인 엔드포인트에서 사용.
    응답에 ``isOwner`` 같은 user-aware 필드를 채울 때만 사용자 객체를 활용.
    """
    if not access_token:
        return None
    claims = decode_access_token(access_token)
    if not claims:
        return None
    user_id_raw = claims.get("sub")
    if not user_id_raw:
        return None
    try:
        user_id = uuid.UUID(user_id_raw)
    except (ValueError, TypeError):
        return None
    return await db.scalar(select(User).where(User.id == user_id))


async def get_current_user(
    user: User | None = Depends(get_optional_user),
) -> User:
    """로그인 필수 — 댓글 작성/AI 분석/즐겨찾기 등."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="로그인이 필요합니다.",
        )
    return user


async def require_admin(
    user: User = Depends(get_current_user),
) -> User:
    """Admin 전용 — NVD/GitHub 토큰 입력, MITRE 백필, 자원 점검."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 권한이 필요합니다.",
        )
    return user
