"""일회성 토큰 서비스 — 이메일 인증 / 비밀번호 재설정 (Redis TTL).

보안 설계:
- 토큰 원문은 ``secrets.token_urlsafe`` (URL-safe, 충분한 엔트로피). 사용자에게는
  원문을 메일 링크로만 전달한다.
- Redis 에는 **SHA-256 해시**로 저장 — Redis 가 유출돼도 저장된 값으로 유효한
  링크를 역산할 수 없다(메일 인증 흐름의 일반 관행).
- **일회성**: 검증 성공 시 즉시 키를 삭제한다(재사용 차단).
- **단일 활성 토큰**: 같은 사용자가 재발송하면 이전 토큰을 무효화한다
  (user→hash 역인덱스). 만료되면 TTL 로 자동 정리.

Redis 장애 시 토큰 발급/검증이 실패하는 게 맞다(인증 흐름은 fail-closed).
"""
from __future__ import annotations

import hashlib
import secrets
import uuid

from app.core.redis_client import get_redis

# 토큰 용도 — Redis 키 네임스페이스 분리.
PURPOSE_EMAIL_VERIFY = "email_verify"
PURPOSE_PASSWORD_RESET = "pwreset"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _key(purpose: str, token_hash: str) -> str:
    return f"kestrel:tok:{purpose}:{token_hash}"


def _user_key(purpose: str, user_id: str) -> str:
    return f"kestrel:tok:{purpose}:user:{user_id}"


async def create_token(purpose: str, user_id: uuid.UUID | str, ttl_seconds: int) -> str:
    """새 일회성 토큰 발급. 같은 사용자의 이전 토큰은 무효화. 원문 토큰 반환."""
    redis = await get_redis()
    uid = str(user_id)

    # 이전 토큰 무효화 — 재발송 시 직전 링크를 죽인다.
    prev_hash = await redis.get(_user_key(purpose, uid))
    if prev_hash:
        await redis.delete(_key(purpose, prev_hash))

    token = secrets.token_urlsafe(32)
    token_hash = _hash(token)
    await redis.set(_key(purpose, token_hash), uid, ex=ttl_seconds)
    await redis.set(_user_key(purpose, uid), token_hash, ex=ttl_seconds)
    return token


async def consume_token(purpose: str, token: str) -> uuid.UUID | None:
    """토큰 검증 + 즉시 폐기(일회성). 유효하면 user_id, 아니면 None."""
    if not token:
        return None
    redis = await get_redis()
    token_hash = _hash(token)
    uid = await redis.get(_key(purpose, token_hash))
    if not uid:
        return None
    # 일회성 — 사용 즉시 본 토큰과 역인덱스 제거.
    await redis.delete(_key(purpose, token_hash))
    await redis.delete(_user_key(purpose, uid))
    try:
        return uuid.UUID(uid)
    except (ValueError, TypeError):
        return None
