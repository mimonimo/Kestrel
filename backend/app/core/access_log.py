"""웹 접속 로그 (Apache access log 스타일) — 요청별 기록 (PR 10-EF).

FastAPI 미들웨어가 매 요청을 Redis capped list 에 남긴다(method·path·status·
응답시간·IP·UA·로그인 사용자). DB 가 아니라 Redis 리스트라 요청당 비용이 작고,
최근 N건만 보존(메모리 bound). 운영자 콘솔에서 조회.

민감정보(쿼리스트링의 토큰 등)는 남기지 않으려 path 만 기록(쿼리 제외).
"""
from __future__ import annotations

import json
import time

import structlog
from starlette.requests import Request

from app.core.redis_client import get_redis
from app.core.request_ip import client_ip
from app.core.security import decode_access_token

log = structlog.get_logger(__name__)

_KEY = "web:access:log"
_CAP = 5000
_TTL = 7 * 86400

# self-noise 방지 — 로그 조회 엔드포인트 자신은 기록하지 않음.
_SKIP_PREFIXES = ("/api/v1/admin/web-access-log",)


def _uid_from_cookie(request: Request) -> str | None:
    token = request.cookies.get("access_token")
    if not token:
        return None
    claims = decode_access_token(token)
    return claims.get("sub") if claims else None


async def record_request(request: Request, status: int, duration_ms: float) -> None:
    """미들웨어에서 호출 — best-effort, 실패해도 요청 흐름에 영향 없음."""
    path = request.url.path
    if request.method == "OPTIONS" or any(path.startswith(p) for p in _SKIP_PREFIXES):
        return
    try:
        entry = json.dumps(
            {
                "ts": time.time(),
                "method": request.method,
                "path": path[:300],
                "status": int(status),
                "ms": round(duration_ms, 1),
                "ip": client_ip(request),
                "ua": (request.headers.get("user-agent") or "")[:512] or None,
                "uid": _uid_from_cookie(request),
            }
        )
        redis = await get_redis()
        await redis.lpush(_KEY, entry)
        await redis.ltrim(_KEY, 0, _CAP - 1)
        await redis.expire(_KEY, _TTL)
    except Exception as exc:  # noqa: BLE001
        log.debug("access_log_record_failed", error=str(exc))


async def read_recent(limit: int) -> list[dict]:
    try:
        redis = await get_redis()
        raw = await redis.lrange(_KEY, 0, limit - 1)
    except Exception as exc:  # noqa: BLE001
        log.warning("access_log_read_failed", error=str(exc))
        return []
    out: list[dict] = []
    for s in raw:
        try:
            out.append(json.loads(s))
        except Exception:  # noqa: BLE001
            continue
    return out
