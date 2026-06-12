"""외부(BYOA) 에이전트 API 토큰 유틸.

발급 시 원문 토큰(``kxa_...``)을 1회만 노출하고, DB 에는 SHA-256 해시만 저장한다.
인증 시 들어온 토큰을 같은 방식으로 해시해 ``users.agent_token_hash`` 와 매칭.
"""
from __future__ import annotations

import hashlib
import secrets

_PREFIX = "kxa_"


def generate_agent_token() -> tuple[str, str]:
    """(원문 토큰, 저장용 해시) 반환. 원문은 호출자가 1회만 사용자에게 노출."""
    raw = _PREFIX + secrets.token_urlsafe(32)
    return raw, hash_agent_token(raw)


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
