"""AI-powered CVE analysis — produces attack method / payload example / mitigation.

Dynamically loads the configured provider, model, and API key from ``app_settings``
(the singleton row managed by the settings API) instead of env vars, so the user
can configure credentials at runtime via the UI without a redeploy.

Both OpenAI and Anthropic are supported. Each provider call returns the same
``AiAnalysis`` shape; the caller doesn't need to care which backend was used.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone


# Claude CLI looks at ``$HOME/.claude/.credentials.json`` for OAuth tokens.
# Dashboard login (PR 10-AD) writes that file directly into the named
# volume at /home/app/.claude, so the analyzer subprocess just inherits
# HOME=/home/app and the CLI handles read + refresh in place. The macOS
# host-bind workaround (PR 10-P) was removed in PR 10-AG.
_NATIVE_CLAUDE_HOME = "/home/app"

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
    "다음 CVE 를 분석해 주세요. 실무자가 결과만으로 PoC 재현 + 패치 구현이 가능해야 합니다.\n\n"
    "CVE ID: {cve_id}\n"
    "제목: {title}\n"
    "설명:\n{description}\n\n"
    "**오직 다음 JSON 만 반환하세요. 마크다운 코드 펜스, 설명, 그 외 텍스트 금지.**\n\n"
    "attack_method (문자열, 한 단락): 취약 컴포넌트·버전 → 전제조건 → 실제 트리거 경로(엔드포인트·파라미터·함수) → 성공 시 영향. "
    "추상 표현 금지, 코드 경로가 무엇을 잘못 처리하는지까지.\n\n"
    "payload_examples (배열, 2-3개): 이 CVE 한정 구체 exploit. 범용 예시 금지. "
    "각 항목 첫 줄 `# 용도: ...`, 마지막 줄 `# 확인 포인트: ...`. "
    "CVE 설명에 등장한 실제 엔드포인트·파라미터·함수명을 그대로 사용. "
    "실제 영향 회수 메커니즘 포함 (XSS → 쿠키 fetch, SQLi → UNION 추출, 명령 인젝션 → 리버스셸/curl, "
    "경로순회 → /etc/shadow 등 민감 파일, SSRF → 메타데이터 엔드포인트, 역직렬화 → gadget chain). "
    "ATTACKER_IP·TARGET_HOST·SESSION_COOKIE 같은 대문자 플레이스홀더 사용.\n\n"
    "mitigations (배열, 3-4개): 각 항목은 위 페이로드의 어느 부분이 어떻게 차단되는지 1:1 매핑. "
    "형식 `[분류] 위치 — 차단 메커니즘`. 분류: 코드패치 / 설정변경 / 입력검증 / WAF·네트워크 / 버전업그레이드. "
    "코드패치는 수정 전/후 스니펫, WAF는 ModSecurity/nginx 룰, 버전업그레이드는 수정 버전 번호. "
    "payload 와 무관한 일반 조언(로그 모니터링·최소 권한 등) 금지."
)

_JSON_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["attack_method", "payload_examples", "mitigations"],
    "properties": {
        "attack_method": {"type": "string"},
        "payload_examples": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "mitigations": {
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
    payload_examples: list[str]   # 다중 PoC — 사용자 요청 (PR 10-R)
    mitigations: list[str]        # 패치 항목 (이전엔 mitigation, 단수)


class AiAnalyzerNotConfigured(HTTPException):
    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


async def _load_active_credential(db: AsyncSession) -> AiCredential:
    settings_row = (
        await db.execute(select(AppSettings).where(AppSettings.id == 1))
    ).scalar_one_or_none()
    if settings_row is None or settings_row.active_credential_id is None:
        raise AiAnalyzerNotConfigured(
            "활성화된 AI 인증이 없어요. 설정 페이지에서 키를 등록하고 사용할 항목을 선택해 주세요.",
        )
    cred = (
        await db.execute(
            select(AiCredential).where(AiCredential.id == settings_row.active_credential_id)
        )
    ).scalar_one_or_none()
    if cred is None:
        raise AiAnalyzerNotConfigured(
            "선택한 AI 인증을 찾을 수 없어요. 설정 페이지에서 다시 활성화해 주세요.",
        )
    # claude_cli uses the host's Claude Code login, not an API key.
    if (cred.provider or "").lower() != "claude_cli" and not cred.api_key:
        raise AiAnalyzerNotConfigured(
            "선택한 인증의 API 키가 비어 있어요. 설정 페이지에서 다시 등록해 주세요.",
        )
    if not cred.provider:
        raise AiAnalyzerNotConfigured("AI 제공자가 지정되지 않았어요.")
    if not cred.model:
        raise AiAnalyzerNotConfigured("AI 모델이 지정되지 않았어요.")
    return cred


def _extract_first_json_object(raw: str) -> dict:
    """Pull the first balanced JSON object out of a free-form text reply.

    LLMs (especially via the claude_cli text path with no force_json) often
    return ``{ ... }\\n\\n해설...`` or markdown like
    ``Here is the analysis:\\n```json\\n{ ... }\\n```\\nLet me know...``.
    Strict ``json.loads`` rejects either of those with "Extra data".

    Strategy:
      1. Strip code fences if present.
      2. Locate the first '{', then use ``raw_decode`` from that offset
         to consume exactly one JSON object — trailing prose is ignored.
      3. If that fails, fall back to the strict whole-string parse so
         the original error surface stays informative.
    """
    text = raw.strip()
    # ``` or ```json fences
    if text.startswith("```"):
        # Drop opening fence + optional language tag
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]
        # Drop trailing fence + anything after (preserve content up to last ```)
        end_fence = text.rfind("```")
        if end_fence != -1:
            text = text[:end_fence]
        text = text.strip()

    # raw_decode from the first '{' so trailing prose is harmless
    start = text.find("{")
    if start != -1:
        decoder = json.JSONDecoder()
        try:
            obj, _end = decoder.raw_decode(text[start:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    # Fallback to strict parse — surfaces the original "Extra data" error
    return json.loads(text)


def _parse_payload(raw: str) -> AiAnalysis:
    """Accept JSON in many shapes: raw object, fenced markdown, or with
    trailing prose. Strict schema check after extraction."""
    # Empty raw = CLI exited 0 but emitted nothing — surfaced as the
    # cryptic "Expecting value: line 1 column 1 (char 0)" parse error
    # before. Distinguish so the user sees an actionable auth hint.
    stripped = raw.strip()
    if not stripped:
        log.warning("ai_analyzer.empty_response")
        raise HTTPException(
            status_code=502,
            detail=(
                "AI 응답이 비어 있습니다. Claude CLI 인증이 만료됐거나 토큰 자동 "
                "갱신이 실패했을 가능성이 큽니다. 설정 → Claude 연동에서 \"다시 "
                "로그인\"을 한 번 눌러 보세요."
            ),
        )
    try:
        data = _extract_first_json_object(stripped)
    except json.JSONDecodeError as e:
        log.exception("ai_analyzer.parse_failed", raw=stripped[:500])
        # Heuristic: if the response looks like an error message (starts
        # with text, no `{`), surface it verbatim instead of a JSON
        # parser error — much more actionable.
        if not stripped.lstrip().startswith("{") and not stripped.lstrip().startswith("```"):
            raise HTTPException(
                status_code=502,
                detail=f"AI 가 JSON 대신 텍스트를 반환했습니다: {stripped[:300]}",
            ) from e
        raise HTTPException(
            status_code=502, detail=f"AI 응답 파싱 실패: {e}"
        ) from e
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="AI 응답이 JSON 객체가 아닙니다.")
    try:
        # Accept both new (payload_examples / mitigations 복수형) and the
        # legacy single-payload shape so cached responses + older AI
        # outputs don't break the panel during the migration window.
        if "payload_examples" in data:
            payloads_raw = data["payload_examples"]
            if not isinstance(payloads_raw, list):
                raise ValueError("payload_examples must be a list")
            payload_examples = [str(p).strip() for p in payloads_raw if str(p).strip()]
        elif "payload_example" in data:
            payload_examples = [str(data["payload_example"]).strip()]
        else:
            raise KeyError("payload_examples")

        mit_raw = data.get("mitigations") or data.get("mitigation")
        if not isinstance(mit_raw, list):
            raise ValueError("mitigations must be a list")
        mitigations = [str(m).strip() for m in mit_raw if str(m).strip()]

        return AiAnalysis(
            attack_method=str(data["attack_method"]).strip(),
            payload_examples=payload_examples,
            mitigations=mitigations,
        )
    except (KeyError, ValueError, TypeError) as e:
        raise HTTPException(status_code=502, detail=f"AI 응답 스키마 불일치: {e}") from e


async def _call_openai_text(
    cred: AiCredential,
    system: str,
    user: str,
    *,
    force_json: bool,
) -> str:
    payload: dict = {
        "model": cred.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    if force_json:
        payload["response_format"] = _build_response_format(cred.provider)
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
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise HTTPException(
            status_code=502, detail=f"{provider_label} 응답 구조 오류: {e}"
        ) from e


async def _call_anthropic_text(cred: AiCredential, system: str, user: str) -> str:
    payload = {
        "model": cred.model,
        "max_tokens": 2048,
        "system": system,
        "messages": [{"role": "user", "content": user}],
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
        chunks = [b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"]
        content = "".join(chunks)
    except (KeyError, TypeError) as e:
        raise HTTPException(status_code=502, detail=f"Anthropic 응답 구조 오류: {e}") from e
    if not content:
        raise HTTPException(status_code=502, detail="Anthropic 응답에 텍스트가 없습니다.")
    return content


_CLI_SELF_UPGRADE_TRIED = False


async def _claude_cli_version() -> str:
    """Return ``claude --version`` first line, or 'unknown' on any failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "claude", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return out.decode("utf-8", errors="replace").strip().splitlines()[0] or "unknown"
    except Exception:
        return "unknown"


async def _try_self_upgrade_claude_cli() -> tuple[bool, str]:
    """Best-effort one-shot ``npm install -g @anthropic-ai/claude-code@latest``.

    Container CLI is pinned to the npm version installed at image build time.
    Host CLI auto-updates and may write the auth file in a newer format the
    container CLI can't read — symptom is silent ``exit 0 + empty stdout``
    or 401 against a freshly-refreshed host token. Bumping the in-container
    CLI to latest at runtime recovers without rebuild.

    Idempotent across the worker process — only runs once per startup so a
    repeated client retry doesn't reinstall every call.
    """
    global _CLI_SELF_UPGRADE_TRIED
    if _CLI_SELF_UPGRADE_TRIED:
        return False, "이번 프로세스에서 이미 시도함"
    _CLI_SELF_UPGRADE_TRIED = True
    if shutil.which("npm") is None:
        return False, "npm 미설치 — INSTALL_CLAUDE_CLI=1 로 빌드된 이미지가 아닙니다."
    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "install", "-g", "@anthropic-ai/claude-code@latest",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=180)
    except asyncio.TimeoutError:
        return False, "npm install 시간 초과 (180s) — 네트워크 확인 필요"
    except Exception as e:
        return False, f"npm install 예외: {e}"
    if proc.returncode != 0:
        diag = (err_b or out_b).decode("utf-8", errors="replace").strip()[:200]
        return False, f"npm install 실패 (exit={proc.returncode}): {diag}"
    return True, "npm install 성공"


async def _call_claude_cli_text(
    cred: AiCredential,
    system: str,
    user: str,
    *,
    _retried_after_upgrade: bool = False,
) -> str:
    """Invoke the local Claude Code CLI in headless mode.

    Uses the OAuth credentials placed in /home/app/.claude by the
    dashboard's Claude 로그인 flow (PR 10-AD). HOME is forced to that
    path so the CLI reads the named-volume credentials regardless of the
    process's inherited environment.

    Failure-handling: any failure (non-zero exit OR exit 0 + empty stdout)
    triggers a one-shot in-container CLI self-upgrade and ONE retry. This
    transparently recovers from version drift between auth-file format
    expected by the runtime CLI vs. the version baked into the image.
    """
    if shutil.which("claude") is None:
        raise HTTPException(
            status_code=502,
            detail=(
                "claude CLI를 찾을 수 없습니다. INSTALL_CLAUDE_CLI=1 (기본값) 로 "
                "백엔드 이미지를 다시 빌드한 뒤 설정 페이지에서 Claude 로그인을 진행해 주세요."
            ),
        )
    prompt = system + "\n\n" + user
    args = [
        "claude",
        "-p",
        prompt,
        "--model",
        cred.model,
        "--output-format",
        "text",
    ]
    env = os.environ.copy()
    env["HOME"] = _NATIVE_CLAUDE_HOME
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            # CRITICAL: close stdin explicitly. Without this the CLI
            # waits 3s for stdin data before proceeding ("Warning: no
            # stdin data received in 3s..."), adding ~3s to every call
            # for no benefit — we always pass the full prompt via -p.
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=502,
            detail="claude CLI 실행 실패: 바이너리를 찾을 수 없습니다.",
        ) from e
    # Timeout — bumped 180s → 360s. Anthropic's deep-analysis calls
    # routinely take 30-90s and a long-CVE prompt with retry on transient
    # network errors can push past the old 3-min ceiling. 6 min is the
    # sweet spot: enough headroom for the slowest legitimate call, still
    # short enough to kill a truly stuck process.
    cli_timeout = 360
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=cli_timeout
        )
    except asyncio.TimeoutError as e:
        proc.kill()
        raise HTTPException(
            status_code=504,
            detail=(
                f"Claude CLI 가 {cli_timeout}초 안에 응답하지 않았어요. "
                "토큰 갱신이 막혔거나 Anthropic 측 지연일 가능성이 있습니다 — "
                "설정 → Claude 연동에서 '다시 로그인' 후 재시도해 주세요."
            ),
        ) from e
    stdout_text = stdout_bytes.decode("utf-8", errors="replace").strip()
    stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()

    failed_exit = proc.returncode != 0
    failed_empty = (not failed_exit) and not stdout_text

    if (failed_exit or failed_empty) and not _retried_after_upgrade:
        prev_version = await _claude_cli_version()
        ok, msg = await _try_self_upgrade_claude_cli()
        if ok:
            new_version = await _claude_cli_version()
            log.info(
                "claude_cli.self_upgraded",
                prev_version=prev_version,
                new_version=new_version,
                trigger="exit_nonzero" if failed_exit else "empty_stdout",
            )
            return await _call_claude_cli_text(
                cred, system, user, _retried_after_upgrade=True
            )
        log.warning(
            "claude_cli.self_upgrade_skipped",
            reason=msg,
            cli_version=prev_version,
        )

    if failed_exit:
        # claude CLI는 인증/모델 오류 같은 사용자 메시지를 stdout으로 내보내는
        # 경우가 많아서, stdout과 stderr를 둘 다 합쳐 보여줘야 진단이 가능합니다.
        diag = (stderr_text or stdout_text or "(출력 없음)")[:600]
        raise HTTPException(
            status_code=502,
            detail=f"claude CLI 실행 실패 (exit={proc.returncode}). 오류: {diag}{_claude_cli_auth_hint(diag)}",
        )
    if failed_empty:
        # exit 0 + empty stdout 도 종종 CLI 버전 drift 또는 인증/구독 만료의
        # silent failure 모드. self-upgrade 가 못 고쳤다면 사용자에게 OAuth
        # 갱신 + 빌드 옵션을 다 알려준다.
        raise HTTPException(
            status_code=502,
            detail=f"claude CLI 응답이 비어 있습니다.{_claude_cli_auth_hint(stderr_text)}",
        )
    # Return raw text — the dispatch contract is `-> str`. Older code
    # called _parse_payload here too, which double-parsed for analysis
    # callers and broke for connectivity-test callers passing
    # force_json=False with plain-text reply ("ok").
    return stdout_text


def _claude_cli_auth_hint(diag: str) -> str:
    """Return a Korean hint when the CLI output looks auth/credential-shaped.

    Three failure modes need different fixes:

      * "not logged in" / "/login" → docker overlay (mount) missing.
      * 401 / invalid credentials / expired → host OAuth token expired
        OR (most common on macOS) host CLI now stores tokens in macOS
        Keychain instead of ``~/.claude/.credentials.json``. Container CLI
        (Linux) can't read Keychain so falls back to the stale legacy file.
        Workaround: run ``backend/scripts/sync_claude_creds_from_keychain.sh``
        on the host to mirror the Keychain token into ``.credentials.json``.
      * Unrecognised diag → no hint (avoid noise).
    """
    lower = diag.lower()
    if "hit your limit" in lower or "rate limit" in lower or "usage limit" in lower:
        return (
            " — Claude 구독 사용량 한도 도달. 한도 reset 시각 이후 재시도하거나 "
            "API key 방식의 다른 provider 로 일시 전환하세요. 인증 자체는 정상."
        )
    if "not logged in" in lower or "/login" in lower:
        return (
            " — 컨테이너 안의 claude CLI가 호스트 로그인을 보지 못합니다. "
            "docker compose에 `-f docker-compose.claude-cli.yml` 오버레이를 "
            "포함해 다시 띄웠는지 확인하세요."
        )
    if (
        "401" in lower
        or "invalid authentication" in lower
        or "authentication_error" in lower
        or "expired" in lower
        or "credentials" in lower
        or not diag  # empty stdout/stderr — assume silent auth degradation
    ):
        return (
            " — claude CLI 인증 실패. macOS 호스트라면 새 CLI 가 OAuth 를 "
            "Keychain('Claude Code-credentials') 에 저장해 컨테이너 mount 로 "
            "공유 안 됩니다. 호스트에서 "
            "`backend/scripts/sync_claude_creds_from_keychain.sh` 한 번 실행하면 "
            "Keychain → ~/.claude/.credentials.json 으로 동기화되고 컨테이너가 "
            "즉시 새 토큰을 읽습니다 (rebuild 불필요). Linux 호스트라면 토큰 "
            "만료일 가능성이 크니 호스트에서 `claude` 한 번 실행하거나 "
            "`claude /login` 으로 새 OAuth flow 를 진행하세요. 그래도 안 되면 "
            "API key 방식의 다른 provider 로 전환하세요."
        )
    return ""


def _extract_error(res: httpx.Response, provider: str) -> str:
    try:
        body = res.json()
        msg = body.get("error", {}).get("message") or body.get("message") or res.text
    except Exception:
        msg = res.text
    return f"{provider} API 오류 ({res.status_code}): {msg[:400]}"


async def _dispatch_text(
    cred: AiCredential,
    system: str,
    user: str,
    *,
    force_json: bool,  # noqa: ARG001 — kept for legacy call sites; claude_cli ignores
) -> str:
    """Dispatch the LLM call. PR 10-T 후 claude_cli 단일 경로만 지원.

    OpenAI/Anthropic/Gemini/Groq/OpenRouter/Cerebras 분기는 사용자 요청
    으로 제거. DB 에 남아 있는 비-claude_cli credential 은 활성화 시도
    가 즉시 명확한 에러로 reject 되어 사용자가 settings 에서 새 키로
    바꾸도록 유도.
    """
    provider = (cred.provider or "").lower()
    if provider == "claude_cli":
        return await _call_claude_cli_text(cred, system, user)
    raise AiAnalyzerNotConfigured(
        f"PR 10-T 이후 claude_cli 만 지원합니다 (현재 활성: {cred.provider}). "
        "설정에서 'Claude Code CLI (로컬 구독)' 으로 새 credential 을 등록하고 활성화하세요."
    )


async def call_llm(
    db: AsyncSession,
    system: str,
    user: str,
    *,
    force_json: bool = True,
) -> str:
    """Public LLM-call helper. Loads the active credential and returns raw text.

    Used by ai_analyzer.analyze_vulnerability and by the sandbox payload-
    adapter / result-analyzer — anything that needs a one-shot prompt
    against whatever provider the user has configured.
    """
    cred = await _load_active_credential(db)
    return await _dispatch_text(cred, system, user, force_json=force_json)


async def ping_active_credential(db: AsyncSession) -> dict:
    """One-shot connectivity test for the *active* AI credential.

    Returns a structured probe result the settings UI can show next to
    the active model — `ok`, `latency_ms`, optional `error_detail` and
    `cli_version` (claude_cli only). The body is one tiny prompt so the
    cost is negligible (~few tokens) but exercises the full auth + HTTP
    + parse path the same way real analysis does.
    """
    started = datetime.now(timezone.utc)
    try:
        cred = await _load_active_credential(db)
    except AiAnalyzerNotConfigured as e:
        return {
            "ok": False,
            "error_kind": "not_configured",
            "error_detail": str(e),
            "latency_ms": 0,
            "provider": None,
            "model": None,
        }
    try:
        text = await _dispatch_text(
            cred,
            "You are a connectivity test responder.",
            "Reply with the exact two characters: ok",
            force_json=False,
        )
    except HTTPException as e:
        elapsed = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        return {
            "ok": False,
            "error_kind": _classify_error(str(e.detail)),
            "error_detail": str(e.detail),
            "latency_ms": elapsed,
            "provider": cred.provider,
            "model": cred.model,
            "cli_version": await _claude_cli_version() if cred.provider == "claude_cli" else None,
        }
    elapsed = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    return {
        "ok": True,
        "reply_preview": (text or "")[:80],
        "latency_ms": elapsed,
        "provider": cred.provider,
        "model": cred.model,
        "cli_version": await _claude_cli_version() if cred.provider == "claude_cli" else None,
    }


def _classify_error(detail: str) -> str:
    """Map an HTTPException detail string to a coarse error_kind tag.

    The settings UI shows different remediation copy per kind — auth
    expired vs. rate-limited vs. config-not-found etc.
    """
    lower = (detail or "").lower()
    if "401" in lower or "invalid authentication" in lower or "expired" in lower:
        return "auth_expired"
    if "rate limit" in lower or "hit your limit" in lower or "usage limit" in lower:
        return "rate_limit"
    if "not logged in" in lower or "/login" in lower:
        return "not_logged_in"
    if "응답이 비어 있습니다" in lower or "empty" in lower:
        return "empty_response"
    if "configuration file not found" in lower or "config" in lower:
        return "config_missing"
    if "not found" in lower or "binary" in lower:
        return "cli_missing"
    return "unknown"


async def analyze_vulnerability(db: AsyncSession, vuln: Vulnerability) -> AiAnalysis:
    user_prompt = _USER_TEMPLATE.format(
        cve_id=vuln.cve_id,
        title=vuln.title,
        description=vuln.description,
    )
    raw = await call_llm(db, _SYSTEM_PROMPT, user_prompt, force_json=True)
    return _parse_payload(raw)


# ─────────────── Follow-up question (free-form) ──────────────────────

_FOLLOWUP_SYSTEM = (
    "당신은 침투 테스트와 취약점 연구 경험이 풍부한 보안 엔지니어입니다. "
    "이전 분석 결과와 사용자가 지금 던지는 추가 질문에 답합니다. "
    "답변은 한국어(존댓말)이며 마크다운을 사용합니다. "
    "추가 사실은 '추정:' 접두사로 명시하고, 코드/PoC 는 ```language 코드블록으로 감쌉니다. "
    "JSON 으로 답하지 말고 사람이 읽기 쉬운 본문으로 작성하세요."
)


def _format_prior_analysis(prior: "AiAnalysis | None") -> str:
    if prior is None:
        return "(이전 분석 결과 없음 — 사용자가 질문만 던졌습니다.)"
    lines = [
        f"### 공격 기법\n{prior.attack_method}",
        "### 페이로드",
    ]
    for i, p in enumerate(prior.payload_examples, 1):
        lines.append(f"  {i}. ```\n{p}\n```")
    lines.append("### 대응 항목")
    for i, m in enumerate(prior.mitigations, 1):
        lines.append(f"  {i}. {m}")
    return "\n\n".join(lines)


async def answer_followup_question(
    db: AsyncSession,
    vuln: Vulnerability,
    prior: "AiAnalysis | None",
    history: list[tuple[str, str]],  # [(question, answer), ...]
    question: str,
) -> str:
    """Free-form Q&A on top of an existing CVE analysis.

    The model gets the prior structured analysis as a memo + any earlier
    Q&A turns so follow-ups can refer to "that payload" or "the second
    mitigation" without the user having to copy-paste.
    """
    parts: list[str] = [
        f"# CVE 컨텍스트\n\nCVE ID: {vuln.cve_id}\n제목: {vuln.title}\n\n## 원문 설명\n{vuln.description}",
        f"# 사전 분석 메모\n\n{_format_prior_analysis(prior)}",
    ]
    if history:
        parts.append("# 지금까지의 Q&A")
        for i, (q, a) in enumerate(history, 1):
            parts.append(f"## 질문 {i}\n{q}\n\n## 답변 {i}\n{a}")
    parts.append(f"# 새 질문\n\n{question}\n\n# 답변")
    user_prompt = "\n\n".join(parts)
    return (await call_llm(db, _FOLLOWUP_SYSTEM, user_prompt, force_json=False)).strip()


# ─────────────── Multi-CVE pattern comparison (JSON) ─────────────────

_COMPARE_SYSTEM = (
    "당신은 침투 테스트와 취약점 연구 경험이 풍부한 보안 엔지니어입니다. "
    "여러 CVE 를 받아 공통 공격 패턴·차이점·통합 완화 전략을 비교 분석합니다. "
    "모든 답변은 한국어(존댓말)이며, 반드시 지정된 JSON 스키마만 반환합니다."
)

_COMPARE_USER_HEADER = (
    "다음 CVE 들을 비교 분석해 주세요. 보안 운영자가 *한 번의 패치/통제로 여러 건을 동시에* "
    "막을 수 있는 공통 약점을 찾는 게 목적입니다.\n\n"
    "JSON 필드 작성 규칙입니다.\n\n"
    "summary (문자열, 한 단락): 이 묶음을 관통하는 핵심 약점/구조적 원인을 한 줄로.\n"
    "common_pattern (문자열, 한 단락): 공통된 공격 흐름·취약 코드 패턴·진입점.\n"
    "differences (문자열 배열, 2~5개): CVE 간 *실제* 차이 — 트리거 조건, 영향 범위, 우회 난이도 등.\n"
    "shared_mitigations (문자열 배열, 2~5개): 묶음 전체를 막는 통제·패치·아키텍처 조치. 일반 조언 금지.\n"
    "per_cve_notes (객체 배열): 각 CVE 별 {cve_id, note} 한 줄 메모 — 이 묶음 안에서의 위치/특이점.\n\n"
)


_COMPARE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "common_pattern", "differences", "shared_mitigations", "per_cve_notes"],
    "properties": {
        "summary": {"type": "string"},
        "common_pattern": {"type": "string"},
        "differences": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "shared_mitigations": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "per_cve_notes": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["cve_id", "note"],
                "properties": {"cve_id": {"type": "string"}, "note": {"type": "string"}},
            },
        },
    },
}


@dataclass
class CompareResult:
    summary: str
    common_pattern: str
    differences: list[str]
    shared_mitigations: list[str]
    per_cve_notes: list[dict]  # [{cve_id, note}]


async def compare_vulnerabilities(
    db: AsyncSession, vulns: list[Vulnerability]
) -> CompareResult:
    """Cross-CVE pattern analysis. 2-5 vulns per call (LLM context limit)."""
    if len(vulns) < 2:
        raise HTTPException(status_code=400, detail="비교 분석은 최소 2건의 CVE 가 필요합니다.")
    if len(vulns) > 5:
        raise HTTPException(status_code=400, detail="한 번에 비교할 수 있는 CVE 는 최대 5건입니다.")

    rows: list[str] = []
    for v in vulns:
        rows.append(
            f"## {v.cve_id}\n제목: {v.title}\n설명:\n{v.description}"
        )
    user_prompt = _COMPARE_USER_HEADER + "\n\n".join(rows)
    raw = await call_llm(db, _COMPARE_SYSTEM, user_prompt, force_json=True)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        # Recover loose JSON from chatty models: take whatever sits between
        # the first { and the matching last }.
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                data = json.loads(raw[start : end + 1])
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=502,
                    detail=f"AI 응답 파싱 실패: {e}",
                ) from e
        else:
            raise HTTPException(
                status_code=502,
                detail=f"AI 응답 파싱 실패: {e}",
            ) from e

    return CompareResult(
        summary=str(data.get("summary", "")).strip(),
        common_pattern=str(data.get("common_pattern", "")).strip(),
        differences=[str(x).strip() for x in (data.get("differences") or [])],
        shared_mitigations=[str(x).strip() for x in (data.get("shared_mitigations") or [])],
        per_cve_notes=[
            {"cve_id": str(n.get("cve_id", "")), "note": str(n.get("note", ""))}
            for n in (data.get("per_cve_notes") or [])
            if isinstance(n, dict)
        ],
    )
