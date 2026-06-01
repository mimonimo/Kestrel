"""방문자 카운터 — Redis SET 으로 unique 추적 (PR 10-CS).

설계: 매 호출이 자신을 카운트한다.
  - 식별자: ``X-Client-Id`` 헤더 (브라우저 부팅 시 발급된 UUID, 모든 요청에
    자동 첨부) 우선. 없으면 클라이언트 IP. 둘 다 없으면 "anon".
  - Redis 키:
      ``visitors:day:<YYYY-MM-DD>`` — 오늘의 unique. 7일 후 자동 만료.
      ``visitors:all``                — 누적 unique. 만료 없음.
  - 응답: ``{ today, total }``.

Public 라우트 — 누구나 조회 가능 (사용자 메뉴 옆 chip 표시용).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header, Request
from pydantic import BaseModel

from app.core.redis_client import get_redis
from app.core.request_ip import client_ip

# 일 방문자 키는 운영자 기준 (KST) 자정에 초기화되어야 한다.
# 서버는 UTC 라 ``date.today()`` 를 그대로 쓰면 KST 09:00 에 바뀌어 사용자가
# "12시 넘었는데 초기화 안 됨" 으로 본다 (PR 10-DI).
_KST = timezone(timedelta(hours=9))

router = APIRouter(prefix="/stats", tags=["stats"])


class VisitorsOut(BaseModel):
    today: int
    total: int


@router.get("/visitors", response_model=VisitorsOut)
async def visitors(
    request: Request,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
) -> VisitorsOut:
    # Caddy 뒤라 request.client.host 는 항상 동일한 docker bridge IP → 실제
    # 사용자 구분 못 함. X-Forwarded-For 우선 (PR 10-DM).
    rid = x_client_id or client_ip(request) or "anon"
    rid = rid[:64]  # bound key size

    day_key = f"visitors:day:{datetime.now(_KST).date().isoformat()}"
    all_key = "visitors:all"

    redis = await get_redis()
    # 멱등 — SADD 는 이미 있으면 no-op.
    await redis.sadd(day_key, rid)
    await redis.sadd(all_key, rid)
    # 오늘 키만 7일 후 자동 정리 (heatmap 등 후속 분석 여지 남기되 무한히 안 쌓이게).
    await redis.expire(day_key, 7 * 86400)

    today_n = await redis.scard(day_key)
    total_n = await redis.scard(all_key)
    return VisitorsOut(today=int(today_n), total=int(total_n))
