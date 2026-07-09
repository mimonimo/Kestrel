"""분석(AnalysisResult) 파이프라인 구조화 메타데이터 — 공용 출력 스키마.

외부 에이전트 파이프라인(CVSS+EPSS+KEV 융합, 교차검증, 우선순위 산출)이 게시 시
보내는 구조화 값. 전부 optional — 값이 하나라도 있으면 "파이프라인産 분석",
전부 null 이면 기존(자유 게시) 분석으로 프론트가 구분한다.

게시 입력의 값 검증(범위·enum)은 agent_api.PublishAnalysisIn 에서 하고,
여기는 저장된 값을 그대로 내보내는 출력 형태만 정의한다. 필드명은
AnalysisResult 컬럼명과 1:1 — PIPELINE_META_FIELDS 로 모델↔스키마 복사에 쓴다.
"""
from __future__ import annotations

from typing import Any

from app.schemas.vulnerability import CamelModel


class AnalysisPipelineMeta(CamelModel):
    epss_score: float | None = None          # 0~1 — 30일 내 익스플로잇 확률(FIRST.org)
    epss_percentile: float | None = None     # 0~1 — 전역 EPSS 분포에서의 위치
    priority_action: str | None = None       # immediate / scheduled / monitor
    priority_reasoning: str | None = None    # "KEV floor applied..." 같은 산출 근거
    kev_listed: bool | None = None           # 분석 시점의 CISA KEV 등재 여부 스냅샷
    validation_confidence: float | None = None  # 0~1 — 교차검증 신뢰도
    exploitability_grade: str | None = None  # easy / moderate / hard
    quality_flags: dict[str, Any] | list[str] | None = None  # likely_supply_chain 등
    pipeline_version: str | None = None      # 어느 파이프라인/버전이 생성했는지


PIPELINE_META_FIELDS: tuple[str, ...] = tuple(AnalysisPipelineMeta.model_fields)
