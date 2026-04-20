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
    "당신은 사이버 보안 전문가입니다. 주어진 CVE 취약점에 대해 공격 기법, "
    "구체적인 공격 페이로드 예시, 그리고 완화 방안을 한국어로 분석합니다. "
    "반드시 지정된 JSON 스키마에 맞는 응답만 반환하세요."
)

_USER_TEMPLATE = (
    "다음 CVE 취약점을 분석해주세요.\n\n"
    "CVE ID: {cve_id}\n"
    "제목: {title}\n"
    "설명:\n{description}\n\n"
    "아래 필드를 포함하는 JSON으로만 응답하세요:\n"
    "- attack_method: 공격 기법을 한두 문단으로 설명 (문자열)\n"
    '- payload_example: 실제 공격 페이로드 예시 코드/명령 (문자열, 원문 그대로)\n'
    "- mitigation: 완화/대응 방안 항목 목록 (문자열 배열, 항목당 한 문장)\n"
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
