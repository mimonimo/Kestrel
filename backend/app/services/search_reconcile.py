"""검색 색인 정합성 점검 — PG 취약점 수 vs Meili 색인 문서 수 (PR perf-A3).

배경: cve_id 오염 등으로 Meili 색인이 DB 보다 적게 유지되는 드리프트가 발생한
적이 있다(취약점 조회 건수 < 대시보드). 주기적으로 두 카운트를 비교해, 임계치
이상 벌어지면 경고 로그(Sentry 포착) + 전수 재색인으로 자동 복구한다.

평상시(정합)에는 카운트 2회 조회만 하는 가벼운 잡이다. 재색인은 드리프트가
실제로 감지될 때만 실행된다(약한 호스트 부하 최소화).
"""
from __future__ import annotations

from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import Vulnerability
from app.services import search_service

log = get_logger(__name__)

# 이 이상 벌어지면 드리프트로 보고 재색인. 증분 수집 타이밍 차로 인한 소량
# 차이(수집 직후 잠깐)는 무시하기 위한 여유.
_DRIFT_THRESHOLD = 100


async def reconcile_search_index() -> dict:
    async with SessionLocal() as session:
        pg = int(
            (await session.execute(select(func.count()).select_from(Vulnerability))).scalar_one()
            or 0
        )
    meili = search_service.meili_document_count()
    drift = pg - meili if meili >= 0 else -1
    log.info("search.reconcile", pg=pg, meili=meili, drift=drift)

    if meili >= 0 and drift > _DRIFT_THRESHOLD:
        log.warning("search.index_drift", pg=pg, meili=meili, drift=drift)
        try:
            queued = await search_service.reindex_all()
            log.info("search.reconcile_reindexed", queued=queued)
        except Exception:
            log.exception("search.reconcile_reindex_failed")
    return {"pg": pg, "meili": meili, "drift": drift}
