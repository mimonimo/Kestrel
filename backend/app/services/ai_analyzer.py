"""AI-powered CVE analysis — produces attack method / payload example / mitigation.

Dynamically loads the configured provider, model, and API key from ``app_settings``
(the singleton row managed by the settings API) instead of env vars, so the user
can configure credentials at runtime via the UI without a redeploy.

Both OpenAI and Anthropic are supported. Each provider call returns the same
``AiAnalysis`` shape; the caller doesn't need to care which backend was used.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models import AiCredential, AppSettings, Vulnerability

log = get_logger(__name__)

_TIMEOUT = httpx.Timeout(60.0, connect=10.0)

_SYSTEM_PROMPT = (
    "당신은 침투 테스트와 취약점 연구 경험이 풍부한 보안 엔지니어입니다. "
    "주어진 CVE에 대해 공격 원리를 설명하고, 직접 실행 가능한 PoC 페이로드를 작성한 뒤, "
    "그 페이로드가 어떻게 차단·무력화되는지 1:1로 매핑되는 패치 방안을 제시합니다. "
    "mitigation 항목은 '방금 작성한 그 페이로드'를 정확히 어떻게 막는지 설명해야 합니다 — "
    "일반적인 '업데이트하세요' 식 조언은 금지입니다. "
    "CVE 설명에 드러나지 않은 사실을 추정한 경우 '추정:' 접두사로 명시하세요. "
    "모든 답변은 한국어(존댓말)이며, 반드시 지정된 JSON 스키마만 반환합니다."
)

_USER_TEMPLATE = (
    "다음 CVE를 분석해 주세요. 실무자가 이 결과만 보고도 공격 재현과 패치 구현이 가능해야 합니다.\n\n"
    "CVE ID: {cve_id}\n"
    "제목: {title}\n"
    "설명:\n{description}\n\n"
    "JSON 필드 작성 규칙입니다.\n\n"
    "attack_method (문자열, 한 단락):\n"
    "  다음 4가지를 순서대로 포함하세요.\n"
    "  (1) 취약한 컴포넌트와 버전 범위, 기본 설정에서 노출되는지 여부\n"
    "  (2) 공격 전제조건 — 인증 필요 여부, 네트워크 위치, 활성화돼야 하는 기능/설정\n"
    "  (3) 실제 트리거 경로 — 어떤 엔드포인트·파라미터·파일 형식·함수 호출이 어떤 내부 로직의 어떤 결함을 건드리는지\n"
    "  (4) 성공 시 영향 — 획득 권한과 후속 피벗 가능성\n"
    "  '악성 페이로드 전송', '취약점을 악용하여' 같은 추상적 표현 금지. 취약한 코드 경로가 무엇을 잘못 처리하는지까지 설명.\n\n"
    "payload_example (문자열, 그대로 복사해 바로 테스트할 수 있는 PoC):\n"
    "  취약점 유형에 맞는 최소 형식만 사용하세요. 불필요한 래퍼(curl/HTTP 전체 요청 등)를 붙이지 마세요.\n"
    "    - XSS / HTML 인젝션 → 주입될 스크립트/HTML 그 자체만 (예: <script>alert(1)</script>, <img src=x onerror=...>)\n"
    "    - SQL 인젝션 → 주입 문자열만 (예: ' OR 1=1-- -)\n"
    "    - 명령 인젝션 → 주입되는 쉘 토큰만 (예: ;id; 또는 $(id))\n"
    "    - 경로 순회 → 순회 문자열만 (예: ../../../../etc/passwd)\n"
    "    - SSRF → 대상 URL 한 줄만 (예: http://169.254.169.254/latest/meta-data/)\n"
    "    - 템플릿 인젝션/역직렬화 등 문자열 주입형 → 주입 문자열만\n"
    "    - 인증 없이 HTTP 요청 자체로 트리거되는 RCE/인증우회 → curl 또는 HTTP 원문, 여러 줄로\n"
    "    - 메모리 손상/로컬 바이너리 대상 → 간단한 python PoC 또는 패턴 설명\n"
    "  주석 규칙:\n"
    "    - 한 줄 페이로드라도 첫 줄에 '# 용도: ...' 주석을 별도 줄로 추가하고, 그 아래에 실제 페이로드를 둡니다.\n"
    "      (주석을 지원하지 않는 형식이면 그대로 페이로드만 써도 됩니다.)\n"
    "    - 페이로드가 여러 줄이면 내부에 '# 핵심: ...' 주석으로 취약 로직을 건드리는 결정적 부분을 지적합니다.\n"
    "    - 마지막 줄에 '# 확인 포인트: ...' 주석으로 성공 판단 기준을 적습니다 (예: 'alert 팝업 발생', '응답 지연 5초 이상').\n"
    "  여러 줄 페이로드의 경우 JSON 문자열 내 줄바꿈은 실제 개행(\\n)으로 표현하고, 한 줄로 압축하지 마세요.\n"
    "  치환값은 TARGET_HOST, ATTACKER_IP, SESSION_COOKIE 등 대문자 플레이스홀더.\n"
    "  실제 타인 자산·개인정보 금지. 테스트 환경 가정으로 작성하세요.\n\n"
    "mitigation (문자열 배열, 3~6개 항목, 우선순위 높은 순):\n"
    "  매우 중요: 각 항목은 위에서 작성한 payload_example 자체가 어떻게 실패하게 되는지를 설명해야 합니다. "
    "  '이 페이로드의 OO 부분이 OO 검사에 걸려 차단됨'처럼 payload의 구체적 요소를 인용하세요.\n"
    "  각 항목 형식: '[분류] 적용 위치·방법 — 이 패치가 적용됐을 때 위 payload의 어느 부분이 왜 실패하는지'\n"
    "  분류는 다음 중 선택: 코드패치 / 설정변경 / 입력검증 / WAF·네트워크 / 버전업그레이드\n"
    "  - 코드패치: 가능한 경우 수정 전/후 코드 스니펫(짧게)이나 함수명·파일 위치 수준의 구체성\n"
    "  - 입력검증: 어떤 정규식·화이트리스트·정규화 처리가 payload의 어느 토큰을 거르는지\n"
    "  - WAF·네트워크: payload의 어떤 문자열을 매칭해서 차단하는지(ModSecurity 규칙 예시 등)\n"
    "  - 버전업그레이드: 수정 버전 번호와, 그 버전에서 payload의 트리거 경로가 어떻게 변경됐는지\n"
    "  payload와 무관한 일반 조언(로그 모니터링, 최소 권한 등)은 포함하지 마세요."
)

_JSON_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["attack_method", "payload_example", "mitigation"],
    "properties": {
        "attack_method": {"type": "string"},
        "payload_example": {"type": "string"},
        "mitigation": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
    },
}

# Providers that speak the OpenAI Chat Completions wire format. Any
# credential with one of these provider values goes through ``_call_openai``;
# the only thing that differs is the base URL (stored on the credential).
_OPENAI_COMPATIBLE = {"openai", "gemini", "groq", "openrouter", "cerebras"}

# Providers whose OpenAI-compatible endpoint is known to accept the full
# ``json_schema`` strict response_format. Others fall back to ``json_object``
# which is far more widely supported; the prompt already tells the model
# exactly which fields to emit.
_SUPPORTS_JSON_SCHEMA = {"openai", "gemini"}


def _build_response_format(provider: str) -> dict:
    if provider in _SUPPORTS_JSON_SCHEMA:
        return {
            "type": "json_schema",
            "json_schema": {
                "name": "cve_analysis",
                "strict": True,
                "schema": _JSON_SCHEMA,
            },
        }
    return {"type": "json_object"}


@dataclass
class AiAnalysis:
    attack_method: str
    payload_example: str
    mitigation: list[str]


class AiAnalyzerNotConfigured(HTTPException):
    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


async def _load_active_credential(db: AsyncSession) -> AiCredential:
    settings_row = (
        await db.execute(select(AppSettings).where(AppSettings.id == 1))
    ).scalar_one_or_none()
    if settings_row is None or settings_row.active_credential_id is None:
        raise AiAnalyzerNotConfigured(
            "활성화된 AI 키가 없습니다. 설정 페이지에서 키를 등록하고 사용할 키를 선택하세요.",
        )
    cred = (
        await db.execute(
            select(AiCredential).where(AiCredential.id == settings_row.active_credential_id)
        )
    ).scalar_one_or_none()
    if cred is None or not cred.api_key:
        raise AiAnalyzerNotConfigured(
            "선택한 AI 키를 찾을 수 없습니다. 설정 페이지에서 다시 선택해주세요.",
        )
    if not cred.provider:
        raise AiAnalyzerNotConfigured("AI 제공자가 설정되지 않았습니다.")
    if not cred.model:
        raise AiAnalyzerNotConfigured("AI 모델이 설정되지 않았습니다.")
    return cred


def _parse_payload(raw: str) -> AiAnalysis:
    """Accept either a raw JSON object or a JSON object wrapped in code fences."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        # Strip optional language hint like "json\n..."
        if "\n" in text:
            first, rest = text.split("\n", 1)
            if len(first) <= 10:  # crude heuristic
                text = rest
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log.exception("ai_analyzer.parse_failed", raw=raw[:500])
        raise HTTPException(status_code=502, detail=f"AI 응답 파싱 실패: {e}") from e
    try:
        mitigation = data["mitigation"]
        if not isinstance(mitigation, list):
            raise ValueError("mitigation must be a list")
        return AiAnalysis(
            attack_method=str(data["attack_method"]).strip(),
            payload_example=str(data["payload_example"]).strip(),
            mitigation=[str(m).strip() for m in mitigation if str(m).strip()],
        )
    except (KeyError, ValueError, TypeError) as e:
        raise HTTPException(status_code=502, detail=f"AI 응답 스키마 불일치: {e}") from e


async def _call_openai(cred: AiCredential, vuln: Vulnerability) -> AiAnalysis:
    payload = {
        "model": cred.model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _USER_TEMPLATE.format(
                    cve_id=vuln.cve_id,
                    title=vuln.title,
                    description=vuln.description,
                ),
            },
        ],
        "response_format": _build_response_format(cred.provider),
    }
    headers = {
        "Authorization": f"Bearer {cred.api_key}",
        "Content-Type": "application/json",
    }
    base = (cred.base_url or "https://api.openai.com/v1").rstrip("/")
    url = f"{base}/chat/completions"
    provider_label = cred.provider.capitalize()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            res = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=502,
            detail=f"{provider_label} 호출 실패 ({url}): {e}",
        ) from e
    if res.status_code >= 400:
        detail = _extract_error(res, provider_label)
        raise HTTPException(status_code=502, detail=detail)
    body = res.json()
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise HTTPException(
            status_code=502, detail=f"{provider_label} 응답 구조 오류: {e}"
        ) from e
    return _parse_payload(content)


async def _call_anthropic(cred: AiCredential, vuln: Vulnerability) -> AiAnalysis:
    payload = {
        "model": cred.model,
        "max_tokens": 2048,
        "system": _SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": _USER_TEMPLATE.format(
                    cve_id=vuln.cve_id,
                    title=vuln.title,
                    description=vuln.description,
                ),
            },
        ],
    }
    headers = {
        "x-api-key": cred.api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        res = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload,
        )
    if res.status_code >= 400:
        detail = _extract_error(res, "Anthropic")
        raise HTTPException(status_code=502, detail=detail)
    body = res.json()
    try:
        # Concatenate all text blocks — Anthropic may split its response.
        chunks = [b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"]
        content = "".join(chunks)
    except (KeyError, TypeError) as e:
        raise HTTPException(status_code=502, detail=f"Anthropic 응답 구조 오류: {e}") from e
    if not content:
        raise HTTPException(status_code=502, detail="Anthropic 응답에 텍스트가 없습니다.")
    return _parse_payload(content)


def _extract_error(res: httpx.Response, provider: str) -> str:
    try:
        body = res.json()
        msg = body.get("error", {}).get("message") or body.get("message") or res.text
    except Exception:
        msg = res.text
    return f"{provider} API 오류 ({res.status_code}): {msg[:400]}"


async def analyze_vulnerability(db: AsyncSession, vuln: Vulnerability) -> AiAnalysis:
    cred = await _load_active_credential(db)
    provider = (cred.provider or "").lower()
    if provider in _OPENAI_COMPATIBLE:
        return await _call_openai(cred, vuln)
    if provider == "anthropic":
        return await _call_anthropic(cred, vuln)
    raise AiAnalyzerNotConfigured(f"지원하지 않는 AI 제공자입니다: {cred.provider}")
