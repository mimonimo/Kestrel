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

# self-noise 방지 + 내부 폴링 제외 — 로그 조회 엔드포인트 자신, 방문자 카운터
# (매 페이지 폴링), 헬스체크는 기록하지 않는다(사용자 접속 분석에 노이즈).
_SKIP_PREFIXES = (
    "/api/v1/admin/web-access-log",
    "/api/v1/admin/access-summary",
    "/api/v1/stats/visitors",
    "/api/v1/healthz",
    "/healthz",
    "/api/v1/health",
    "/health",
    "/api/v1/status",
    "/status",
)

# 내부망/루프백 — 헬스체크·SSR·컨테이너 간 호출 출처. 사용자 접속이 아님.
_HEALTH_PATHS = _SKIP_PREFIXES


def _is_internal_ip(ip: str | None) -> bool:
    """루프백·사설 대역(컨테이너 브리지 172.x, 10.x, 192.168.x)·미상은 내부로 간주."""
    if not ip:
        return True
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip == "localhost"
    return addr.is_loopback or addr.is_private


def _is_noise(rec: dict) -> bool:
    path = rec.get("path") or ""
    return _is_internal_ip(rec.get("ip")) or any(path.startswith(h) for h in _HEALTH_PATHS)


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
    # 내부 트래픽(헬스체크·SSR·컨테이너 간 호출)은 Caddy 를 거치지 않아
    # X-Forwarded-For / X-Real-IP 헤더가 없다. 외부 사용자는 반드시 Caddy 를
    # 경유하므로 두 헤더가 모두 없으면 사용자 접속이 아님 → 기록 제외.
    if not request.headers.get("x-forwarded-for") and not request.headers.get("x-real-ip"):
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


async def _filter_list(redis, key: str, keep_pred) -> None:
    """list 를 읽어 keep_pred(rec)==True 인 항목만 남기고 재작성(순서 유지)."""
    raw = await redis.lrange(key, 0, -1)
    keep: list[str] = []
    for s in raw:
        try:
            rec = json.loads(s)
        except Exception:  # noqa: BLE001 — 파싱 실패 항목은 그대로 보존
            keep.append(s)
            continue
        if keep_pred(rec):
            keep.append(s)
    pipe = redis.pipeline()
    pipe.delete(key)
    if keep:
        pipe.rpush(key, *keep)  # lrange(head→tail) 순서대로 다시 넣어 최신순 유지
        pipe.expire(key, _TTL)
    await pipe.execute()


async def clear(
    *,
    ips: list[str] | None = None,
    uids: list[str] | None = None,
    noise: bool = False,
) -> None:
    """접속 로그 삭제.

    - noise=True: 내부/헬스체크 등 노이즈 항목만 제거(기존 적재분 정리).
    - ips/uids 지정: 해당 IP·회원 항목만 제거(다중 선택 가능).
    - 모두 미지정: 전체 삭제.
    """
    redis = await get_redis()
    if noise:
        await _filter_list(redis, _KEY, lambda r: not _is_noise(r))
        await _filter_list(redis, "visitors:anon:log", lambda r: not _is_internal_ip(r.get("ip")))
        return
    ipset = {i for i in (ips or []) if i}
    uidset = {u for u in (uids or []) if u}
    if not ipset and not uidset:
        await redis.delete(_KEY, "visitors:anon:log")
        return
    # 부분 삭제 — 조건에 맞는 항목만 제외하고 재작성.
    await _filter_list(
        redis,
        _KEY,
        lambda r: not (r.get("ip") in ipset or r.get("uid") in uidset),
    )
    if ipset:
        # 비회원 방문 로그도 같은 IP 제외.
        await _filter_list(redis, "visitors:anon:log", lambda r: r.get("ip") not in ipset)


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
