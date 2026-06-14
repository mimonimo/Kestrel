"""집계 스냅샷 — 무거운 대시보드/검색 facets 집계를 *주기적으로* 미리 계산해
Redis 에 저장하고, API 는 요청 시 이 스냅샷을 즉시 반환한다 (PR perf-A2).

배경: affected_products 가 ~288만 행으로 커지면서 facets 의
``count(distinct vulnerability_id)`` 와 dashboard 의 시계열/벤더 집계가
매 요청마다 수십 초씩 걸려(2 vCPU/2GB) 타임아웃이 발생했다. 이 데이터는
수집 주기(~30분)에만 바뀌므로 실시간일 필요가 없다 → 스케줄러가 10분마다
한 번 계산(백그라운드, statement_timeout 미적용)해 두고, 사용자 요청은
캐시된 스냅샷을 ms 단위로 받는다.

스냅샷은 *기본 파라미터*(필터 없는 facets / days=30 insights / 기본 priorities)
만 담는다 — 프론트 대시보드·검색 첫 로드가 정확히 이 형태다. 필터/비기본
파라미터 요청은 결과 집합이 좁아 빠르므로 기존 라이브 경로로 계산한다.
"""
from __future__ import annotations

from app.core.logging import get_logger
from app.core.redis_client import get_redis

log = get_logger(__name__)

# 스냅샷 Redis 키 (스키마 변경 시 vN 올려 무효화).
SNAP_FACETS = "kestrel:snap:facets:v1"
SNAP_PRIORITIES = "kestrel:snap:priorities:v1"


def insights_snap_key(days: int) -> str:
    """대시보드 insights 는 기간 토글(7/30/90일)마다 별도 캐시."""
    return f"kestrel:snap:insights:v1:{days}"


# 안전 만료 — 스케줄러가 10분마다 갱신하지만, 스케줄러가 죽어도 1시간 뒤
# 스냅샷이 사라져 라이브 경로(최신값)로 폴백하도록 한다.
_SNAPSHOT_TTL = 3600

# 프론트가 실제 보내는 기본 파라미터 — 이 형태만 스냅샷으로 캐싱.
# CvssBucketsPanel / TimelinePanel 의 기간 토글이 7·30·90일이므로 모두 캐싱한다
# (안 하면 7/90일이 라이브 집계 → statement_timeout 500).
INSIGHTS_DAYS = (7, 30, 90)
INSIGHTS_VENDOR_LIMIT = 10
INSIGHTS_RECENT_LIMIT = 5
PRIORITIES_DEFAULT_PER_BUCKET = 5


async def get_snapshot(key: str) -> str | None:
    """저장된 스냅샷 JSON 문자열 반환. 없거나 Redis 장애면 None(→ 라이브 폴백)."""
    try:
        redis = await get_redis()
        return await redis.get(key)
    except Exception:  # noqa: BLE001 — 캐시 미스/장애는 라이브 계산으로 폴백
        return None


async def refresh_snapshots() -> None:
    """무거운 집계 3종을 계산해 Redis 에 저장. 스케줄러가 주기 호출.

    백그라운드 전용 풀(background_session, statement_timeout=0)이라 무거운 집계가
    잘리지 않고 끝까지 계산한다. 각 항목은 독립적으로 try — 하나가 실패해도
    나머지는 저장한다. 순환 import 회피를 위해 라우트 모듈의 계산 함수는 지연 import.
    """
    # 지연 import — search/dashboard 라우트 모듈(무거운 의존성)을 모듈 로드시점이
    # 아니라 실행시점에 가져온다.
    from app.api.v1.dashboard import _compute, _compute_priorities
    from app.api.v1.search import _build_facets

    from app.core.database import background_session

    redis = await get_redis()
    # background_session: 풀 커넥션이 API 요청에서 남긴 statement_timeout(20s)을
    # 물려받아 무거운 집계가 잘리는 것을 막는다(timeout 해제).
    async with background_session() as session:

        try:
            facets = await _build_facets(session)
            await redis.set(SNAP_FACETS, facets.model_dump_json(by_alias=True), ex=_SNAPSHOT_TTL)
        except Exception:
            await session.rollback()
            log.exception("snapshot.facets_failed")

        for days in INSIGHTS_DAYS:
            try:
                insights = await _compute(
                    session,
                    days=days,
                    vendor_limit=INSIGHTS_VENDOR_LIMIT,
                    recent_limit=INSIGHTS_RECENT_LIMIT,
                )
                await redis.set(
                    insights_snap_key(days),
                    insights.model_dump_json(by_alias=True),
                    ex=_SNAPSHOT_TTL,
                )
            except Exception:
                await session.rollback()
                log.exception("snapshot.insights_failed", days=days)

        try:
            pri = await _compute_priorities(session, per_bucket=PRIORITIES_DEFAULT_PER_BUCKET)
            await redis.set(
                SNAP_PRIORITIES, pri.model_dump_json(by_alias=True), ex=_SNAPSHOT_TTL
            )
        except Exception:
            await session.rollback()
            log.exception("snapshot.priorities_failed")

    log.info("snapshot.refresh_done")
