"""Adapt a generic AI-generated CVE exploit payload to a specific lab's
injection point.

The CVE-analysis prompt produces a payload that uses placeholders like
``TARGET_HOST`` and refers to vulnerable endpoints in the wild — e.g.
WordPress's ``/wp-admin/edit.php?post=…``. The lab we spawn is a generic
class-level target, so we ask the LLM to rewrite the payload to fit the
lab's actual method/path/parameter while preserving the *technique* (the
encoding tricks, the filter bypass, the exfiltration channel).

Returns a structured object the manager can replay verbatim.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.services.ai_analyzer import call_llm
from app.services.sandbox.catalog import LabDefinition

log = get_logger(__name__)


@dataclass
class AdaptedPayload:
    method: str
    path: str
    parameter: str
    location: str  # "query" | "form" | "json" | "header"
    payload: str
    success_indicator: str  # human-readable hint for verification
    rationale: str
    notes: str = ""
    raw: dict = field(default_factory=dict)


_SYSTEM = (
    "당신은 침투 테스트 자동화 엔진입니다. 주어진 CVE 분석 결과(공격 기법·페이로드)를 "
    "지정된 로컬 실습 환경(lab)의 실제 엔드포인트와 파라미터에 맞게 다시 작성하는 일을 합니다. "
    "기법(인코딩·필터 우회·exfil 채널)은 보존하되, 외부 호스트·실제 CVE 대상 경로 같은 "
    "구체적 사실은 lab의 값으로 치환해야 합니다. 절대 추측해서 외부 IP나 도메인을 새로 "
    "만들지 마세요. 응답은 한국어 키 없이, 지정된 JSON 스키마만 반환합니다."
)

_USER_TEMPLATE = """\
## CVE 정보
- CVE ID: {cve_id}
- 제목: {title}
- 설명:
{description}

## CVE 분석에서 만든 일반 페이로드
{generic_payload}

## 사용 가능한 실습 환경
종류: {lab_kind}
설명: {lab_description}
타깃 base URL (네트워크 내부): {target_url}

주입 지점 후보 (이 중 가장 적합한 한 곳을 골라 사용):
{injection_points_json}

## 작업
generic_payload의 기법을 보존하면서, 위 주입 지점 중 하나에 실제로 동작할 수 있는 형태로
페이로드를 다시 작성하세요. ATTACKER_IP·외부 도메인 같은 placeholder는 lab의 다른 주입
지점이 자체적으로 보여줄 수 있는 형태(예: <script>document.body.innerText='XSS_OK'</script>)로
대체하거나, 응답 본문에 직접 흔적이 남는 방식으로 바꾸세요.

JSON 스키마:
{{
  "method": "GET" | "POST",
  "path": "/...",
  "parameter": "...",
  "location": "query" | "form" | "json" | "header",
  "payload": "실제 전송할 값 (이스케이프된 문자열)",
  "success_indicator": "응답에서 무엇을 발견하면 성공으로 볼지 사람이 읽을 수 있는 한 문장",
  "rationale": "왜 이 주입 지점/형태로 결정했는지 1~2문장",
  "notes": ""
}}
"""


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if "\n" in t:
            first, rest = t.split("\n", 1)
            if len(first) <= 10:
                t = rest
    return t.strip()


def _injection_points_dump(lab: LabDefinition) -> str:
    return json.dumps(
        [
            {
                "name": ip.name,
                "method": ip.method,
                "path": ip.path,
                "parameter": ip.parameter,
                "location": ip.location,
                "response_kind": ip.response_kind,
                "notes": ip.notes,
            }
            for ip in lab.injection_points
        ],
        ensure_ascii=False,
        indent=2,
    )


async def adapt_payload(
    db: AsyncSession,
    *,
    cve_id: str,
    title: str,
    description: str,
    generic_payload: str,
    target_url: str,
    lab: LabDefinition,
) -> AdaptedPayload:
    user = _USER_TEMPLATE.format(
        cve_id=cve_id,
        title=title,
        description=description,
        generic_payload=generic_payload or "(기존 분석 결과 없음 — CVE 정보만 보고 작성)",
        lab_kind=lab.kind,
        lab_description=lab.description,
        target_url=target_url,
        injection_points_json=_injection_points_dump(lab),
    )
    raw = await call_llm(db, _SYSTEM, user, force_json=True)
    try:
        data = json.loads(_strip_fence(raw))
    except json.JSONDecodeError as e:
        log.warning("sandbox.adapt_parse_failed", raw=raw[:400])
        raise HTTPException(
            status_code=502, detail=f"AI 페이로드 적응 응답 파싱 실패: {e}"
        ) from e

    valid_paths = {ip.path for ip in lab.injection_points}
    chosen_path = str(data.get("path", "")).strip()
    if chosen_path not in valid_paths:
        # AI hallucinated a path. Fall back to the first injection point.
        first = lab.injection_points[0]
        log.warning(
            "sandbox.adapt_unknown_path",
            chosen=chosen_path,
            valid=list(valid_paths),
        )
        chosen_path = first.path
        data.setdefault("method", first.method)
        data.setdefault("parameter", first.parameter)
        data.setdefault("location", first.location)

    return AdaptedPayload(
        method=str(data.get("method", "GET")).upper(),
        path=chosen_path,
        parameter=str(data.get("parameter", "")),
        location=str(data.get("location", "query")),
        payload=str(data.get("payload", "")),
        success_indicator=str(data.get("success_indicator", "")),
        rationale=str(data.get("rationale", "")),
        notes=str(data.get("notes", "")),
        raw=data,
    )
