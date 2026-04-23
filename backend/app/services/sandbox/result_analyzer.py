"""Ask the LLM to judge whether a sandbox HTTP exchange shows the exploit
fired, and what to try next if it didn't.

Cheap heuristic-first: if the response body contains the literal
``payload`` string and looks like an HTML reflection, we already know it's
a confirmed reflected XSS without spending a model call. The AI is invoked
either way to provide qualitative feedback, but the heuristic answer is
returned alongside so the UI can show a deterministic verdict even if the
LLM is offline.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.services.ai_analyzer import call_llm
from app.services.sandbox.payload_adapter import AdaptedPayload

log = get_logger(__name__)


@dataclass
class RunVerdict:
    success: bool
    confidence: str  # "high" | "medium" | "low"
    summary: str
    evidence: str = ""
    next_step: str = ""
    heuristic_signal: str = ""
    raw: dict = field(default_factory=dict)


_SYSTEM = (
    "당신은 격리된 실습 환경에서 페이로드 한 번을 보낸 결과를 보고, 공격이 통했는지 "
    "판정하는 분석가입니다. 응답 본문에 페이로드의 흔적이 그대로 남았는지, 의도한 효과가 "
    "발현되었는지를 보세요. 한국어 JSON만 반환합니다."
)

_USER_TEMPLATE = """\
## 컨텍스트
- CVE ID: {cve_id}
- 제목: {title}
- lab 종류: {lab_kind}
- 성공 판정 힌트: {success_indicator}

## 보낸 페이로드
- {method} {path}  ({location} 파라미터 `{parameter}`)
- payload: {payload}

## 받은 응답
- HTTP {status_code}
- 본문 (앞부분):
{body_excerpt}

## 작업
다음 JSON으로만 응답:
{{
  "success": true | false,
  "confidence": "high" | "medium" | "low",
  "summary": "한 문장으로 결과 요약",
  "evidence": "응답에서 그렇게 판단한 근거 (응답 본문의 짧은 인용 가능)",
  "next_step": "실패한 경우 다음에 시도할 페이로드 변형의 핵심 아이디어 한 줄, 성공이면 빈 문자열"
}}
"""


def _heuristic(adapted: AdaptedPayload, exchange: dict) -> str:
    """Cheap rule-based check that doesn't need the LLM."""
    body = exchange.get("body") or ""
    payload = adapted.payload or ""
    if not payload:
        return "no-payload"
    if payload in body:
        return "payload-reflected"
    return "payload-not-reflected"


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if "\n" in t:
            first, rest = t.split("\n", 1)
            if len(first) <= 10:
                t = rest
    return t.strip()


async def analyze_run(
    db: AsyncSession,
    *,
    cve_id: str,
    title: str,
    lab_kind: str,
    adapted: AdaptedPayload,
    exchange: dict,
) -> RunVerdict:
    body = exchange.get("body") or ""
    excerpt = body[:2000]
    user = _USER_TEMPLATE.format(
        cve_id=cve_id,
        title=title,
        lab_kind=lab_kind,
        success_indicator=adapted.success_indicator or "(없음)",
        method=adapted.method,
        path=adapted.path,
        location=adapted.location,
        parameter=adapted.parameter,
        payload=adapted.payload,
        status_code=exchange.get("status_code"),
        body_excerpt=excerpt or "(응답 본문 없음)",
    )

    heuristic = _heuristic(adapted, exchange)

    try:
        raw = await call_llm(db, _SYSTEM, user, force_json=True)
        data = json.loads(_strip_fence(raw))
    except (HTTPException, json.JSONDecodeError) as e:
        log.warning("sandbox.verdict_failed", error=str(e))
        # Fall back to heuristic-only verdict so the UI still shows something.
        return RunVerdict(
            success=heuristic == "payload-reflected",
            confidence="low",
            summary=(
                "AI 판정 호출에 실패해 휴리스틱만 사용했습니다. "
                + ("페이로드가 응답 본문에 그대로 반영됨." if heuristic == "payload-reflected" else "페이로드 흔적이 응답에서 발견되지 않음.")
            ),
            evidence="",
            next_step="",
            heuristic_signal=heuristic,
            raw={"error": str(e)},
        )

    return RunVerdict(
        success=bool(data.get("success", False)),
        confidence=str(data.get("confidence", "medium")),
        summary=str(data.get("summary", "")),
        evidence=str(data.get("evidence", "")),
        next_step=str(data.get("next_step", "")),
        heuristic_signal=heuristic,
        raw=data,
    )
