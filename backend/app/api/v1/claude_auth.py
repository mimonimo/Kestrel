"""Dashboard-driven Claude OAuth login.

PR 10-AD initially drove ``claude setup-token`` inside the container via a
PTY. That CLI ended up hanging silently at the OAuth token-exchange step
on some setups (Bun-compiled native binary, root cause not visible to us),
so PR 10-AS replaces the PTY path with a direct backend-side OAuth 2.0 +
PKCE exchange:

    1. ``POST /start`` — backend generates ``code_verifier`` /
       ``code_challenge`` (PKCE) and a random ``state``, constructs the
       authorize URL with the Claude Code CLI's known public ``client_id``,
       and stores the verifier in an in-memory session. Returns the URL.
    2. User visits the URL, authenticates on Anthropic, lands on the
       redirect_uri callback page, and copies the displayed code
       (typically ``<code>#<state>``) back to our UI.
    3. ``POST /{sid}/submit`` — backend splits ``<code>#<state>``,
       verifies the state matches the session, then POSTs to Anthropic's
       token endpoint with the code + our stored verifier. On 200 it
       writes the credentials to the same ``.credentials.json`` shape the
       CLI used to write, so all downstream code paths (status read, AI
       analyzer, sandbox synthesizer) keep working unchanged.

Why bypass the CLI?
    The in-container ``claude setup-token`` flow consistently hit a
    60-second backend timeout: CLI mask-echoed the pasted code (so input
    plumbing was fine), then went silent while doing the token exchange
    internally. Doing the same HTTP exchange ourselves removes the
    opaque binary from the critical path and surfaces real Anthropic
    error responses to the user.

A separate ``POST /credentials`` endpoint accepts a pre-existing
``.credentials.json`` content (escape hatch for users who can run the
CLI elsewhere and want to copy the result over).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.logging import get_logger
from app.models import AiCredential, AppSettings

router = APIRouter(prefix="/settings/claude-auth", tags=["claude-auth"])
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# OAuth constants (extracted from the Claude Code CLI's bundled config)
# ---------------------------------------------------------------------------

_OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
_OAUTH_AUTH_URL = "https://claude.com/cai/oauth/authorize"
_OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
_OAUTH_REDIRECT_URI = "https://platform.claude.com/oauth/code/callback"
_OAUTH_SCOPE = "user:inference"


# ---------------------------------------------------------------------------
# Pydantic models (camelCase responses)
# ---------------------------------------------------------------------------

class _CamelOut(BaseModel):
    model_config = ConfigDict(
        from_attributes=True, alias_generator=to_camel, populate_by_name=True
    )


class StatusOut(_CamelOut):
    """Current login state — what the settings panel renders on mount."""

    logged_in: bool
    expires_at: int | None = None  # epoch milliseconds (matches CLI)
    scopes: list[str] = []
    cli_present: bool
    cli_version: str | None = None


class StartOut(_CamelOut):
    """Returned right after the OAuth URL is captured."""

    session_id: str
    url: str
    expires_in_seconds: int = 600  # 10 min hard cap on the login session


class SubmitIn(_CamelOut):
    code: str = Field(min_length=4, max_length=4096)


class ActionOut(_CamelOut):
    ok: bool
    detail: str


class CredentialsIn(_CamelOut):
    """Raw ``.credentials.json`` content the user pastes manually.

    Escape hatch for users who already have a working credentials file
    (e.g. ``claude setup-token`` succeeded on their dev machine).
    """

    credentials: dict[str, Any] | str


# ---------------------------------------------------------------------------
# Login session registry (in-memory; single backend instance assumed)
# ---------------------------------------------------------------------------

_CLAUDE_HOME = Path("/home/app/.claude")
_CRED_FILE = _CLAUDE_HOME / ".credentials.json"
_SESSION_TTL_SECONDS = 600  # 10 min — caps a forgotten OAuth tab


@dataclass
class _LoginSession:
    sid: str
    code_verifier: str
    state: str
    url: str
    started_at: float


_sessions: dict[str, _LoginSession] = {}
_sessions_lock = asyncio.Lock()


def _gc_sessions() -> None:
    """Reap sessions older than the TTL — keeps the registry bounded."""
    now = time.time()
    stale = [
        sid for sid, s in _sessions.items() if now - s.started_at > _SESSION_TTL_SECONDS
    ]
    for sid in stale:
        _sessions.pop(sid, None)


# ---------------------------------------------------------------------------
# PKCE helpers (RFC 7636)
# ---------------------------------------------------------------------------

def _b64url(b: bytes) -> str:
    """URL-safe base64 without padding — what OAuth PKCE expects."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _pkce_pair() -> tuple[str, str]:
    """Generate (verifier, challenge) per RFC 7636 §4.

    Verifier: 32 random bytes → ~43 base64url chars.
    Challenge: base64url(SHA-256(verifier)).
    """
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def _build_authorize_url(challenge: str, state: str) -> str:
    """Construct the URL the user opens to authenticate with Anthropic.

    Matches the Claude Code CLI's authorize request 1:1 (we discovered the
    parameters by reading the CLI's emitted URL). ``code=true`` is the
    Anthropic-specific flag that tells the OAuth page to display the
    code instead of redirecting to a backend; it does not replace the
    standard ``response_type=code``.
    """
    from urllib.parse import urlencode

    params = {
        "code": "true",
        "client_id": _OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": _OAUTH_REDIRECT_URI,
        "scope": _OAUTH_SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{_OAUTH_AUTH_URL}?{urlencode(params)}"


# ---------------------------------------------------------------------------
# Credentials file inspection
# ---------------------------------------------------------------------------

def _read_credentials() -> dict[str, Any] | None:
    if not _CRED_FILE.exists():
        return None
    try:
        return json.loads(_CRED_FILE.read_text())
    except Exception:
        return None


def _write_credentials(payload: dict[str, Any]) -> None:
    _CLAUDE_HOME.mkdir(parents=True, exist_ok=True)
    _CRED_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    os.chmod(_CRED_FILE, 0o600)


def _claude_version() -> str | None:
    """Optional — the CLI is no longer required for login, but if it's
    installed the settings panel still surfaces its version so the user
    knows whether the AI analyzer path that *does* exec the CLI will work.
    """
    if shutil.which("claude") is None:
        return None
    try:
        import subprocess as _sp

        out = _sp.run(
            ["claude", "--version"], capture_output=True, text=True, timeout=5
        )
        return (out.stdout or out.stderr or "").strip() or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/status", response_model=StatusOut, response_model_by_alias=True)
async def status_route() -> StatusOut:
    creds = _read_credentials()
    cli_version = _claude_version()
    if creds is None:
        return StatusOut(
            logged_in=False,
            cli_present=cli_version is not None,
            cli_version=cli_version,
        )
    oauth = creds.get("claudeAiOauth") or {}
    expires_at = oauth.get("expiresAt")
    return StatusOut(
        logged_in=True,
        expires_at=int(expires_at) if expires_at is not None else None,
        scopes=list(oauth.get("scopes") or []),
        cli_present=cli_version is not None,
        cli_version=cli_version,
    )


@router.post("/start", response_model=StartOut, response_model_by_alias=True)
async def start_route() -> StartOut:
    async with _sessions_lock:
        _gc_sessions()
    verifier, challenge = _pkce_pair()
    state = _b64url(secrets.token_bytes(32))
    sid = secrets.token_urlsafe(16)
    url = _build_authorize_url(challenge, state)
    sess = _LoginSession(
        sid=sid,
        code_verifier=verifier,
        state=state,
        url=url,
        started_at=time.time(),
    )
    async with _sessions_lock:
        _sessions[sid] = sess
    log.info("claude_auth.session_started", sid=sid)
    return StartOut(session_id=sid, url=url)


_DEFAULT_LABEL = "Claude 구독 (대시보드 로그인)"
_DEFAULT_PROVIDER = "claude_cli"
_DEFAULT_MODEL = "claude-sonnet-4-6"


async def _ensure_active_credential(db: AsyncSession) -> AiCredential:
    """Make sure there's exactly one ``claude_cli`` credential and it's active.

    Called right after a successful login so the user doesn't have to
    also visit the model-label form to activate something — the analyzer
    can immediately route to the freshly-saved OAuth.
    """
    cred = (
        await db.execute(
            select(AiCredential)
            .where(AiCredential.provider == _DEFAULT_PROVIDER)
            .order_by(AiCredential.id.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if cred is None:
        cred = AiCredential(
            label=_DEFAULT_LABEL,
            provider=_DEFAULT_PROVIDER,
            model=_DEFAULT_MODEL,
            # claude_cli reads OAuth from disk; the api_key column is
            # NOT NULL so a sentinel keeps the schema happy.
            api_key="oauth-from-disk",
        )
        db.add(cred)
        await db.flush()

    settings_row = (
        await db.execute(select(AppSettings).where(AppSettings.id == 1))
    ).scalar_one_or_none()
    if settings_row is None:
        settings_row = AppSettings(id=1)
        db.add(settings_row)
    settings_row.active_credential_id = cred.id
    await db.commit()
    await db.refresh(cred)
    return cred


def _parse_code_input(raw: str, expected_state: str) -> str:
    """Validate and extract the OAuth ``code`` from the user's paste.

    The Anthropic callback page displays the code as either ``<code>``
    alone or ``<code>#<state>`` (we've seen both in the wild). If a
    state suffix is present it MUST match the session's state — otherwise
    we'd be exchanging a code that belongs to a different OAuth attempt.
    """
    cleaned = raw.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    if "#" in cleaned:
        code, _, state = cleaned.partition("#")
        if state and state != expected_state:
            raise HTTPException(
                status_code=400,
                detail=(
                    "코드의 state 부분이 현재 세션과 일치하지 않습니다. "
                    "다시 로그인을 시작한 뒤 새 URL 에서 받은 코드를 사용하세요."
                ),
            )
        return code
    return cleaned


@router.post(
    "/{session_id}/submit",
    response_model=ActionOut,
    response_model_by_alias=True,
)
async def submit_route(
    session_id: str,
    body: SubmitIn,
    db: AsyncSession = Depends(get_db),
) -> ActionOut:
    async with _sessions_lock:
        sess = _sessions.get(session_id)
    if sess is None:
        raise HTTPException(
            status_code=404,
            detail="로그인 세션을 찾을 수 없습니다. 다시 시작해 주세요.",
        )
    if time.time() - sess.started_at > _SESSION_TTL_SECONDS:
        async with _sessions_lock:
            _sessions.pop(session_id, None)
        raise HTTPException(
            status_code=410,
            detail="로그인 세션이 만료되었습니다 (10분). 다시 시작해 주세요.",
        )

    code = _parse_code_input(body.code, sess.state)
    if not code:
        raise HTTPException(
            status_code=400,
            detail="코드가 비어 있습니다.",
        )

    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "state": sess.state,
        "client_id": _OAUTH_CLIENT_ID,
        "redirect_uri": _OAUTH_REDIRECT_URI,
        "code_verifier": sess.code_verifier,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.post(
                _OAUTH_TOKEN_URL,
                json=token_payload,
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as e:
        log.exception("claude_auth.token_exchange_http_error")
        raise HTTPException(
            status_code=502,
            detail=f"Anthropic 토큰 엔드포인트 호출 실패: {e}",
        ) from e

    if res.status_code >= 400:
        try:
            err_body = res.json()
        except Exception:
            err_body = {"text": res.text[:400]}
        msg = (
            (err_body.get("error") or {}).get("message")
            if isinstance(err_body.get("error"), dict)
            else None
        )
        if not msg:
            msg = err_body.get("error_description") or err_body.get("error") or res.text[:400]
        log.warning(
            "claude_auth.token_exchange_failed",
            status=res.status_code,
            body=str(err_body)[:400],
        )
        # The exchange itself is the typical failure point for "잘못된
        # 코드 / 만료된 코드 / state 불일치" — surface Anthropic's own
        # error verbatim so the user can see what's wrong.
        raise HTTPException(
            status_code=400,
            detail=(
                f"Anthropic 토큰 교환 실패 ({res.status_code}): {str(msg)[:400]}. "
                "코드가 이미 사용됐거나 만료되었을 수 있습니다 — 다시 로그인 시작."
            ),
        )

    try:
        body_json = res.json()
        access_token = body_json["access_token"]
        refresh_token = body_json.get("refresh_token")
        # ``expires_in`` is seconds-until-expiry; we store an absolute epoch.
        expires_in = int(body_json.get("expires_in") or 0)
        # Scope echoes what the server actually granted; may differ from
        # what we requested.
        scope = body_json.get("scope") or _OAUTH_SCOPE
        scopes = scope.split() if isinstance(scope, str) else list(scope)
    except (KeyError, ValueError, TypeError) as e:
        log.exception("claude_auth.token_response_parse_failed")
        raise HTTPException(
            status_code=502,
            detail=f"Anthropic 토큰 응답 파싱 실패: {e}",
        ) from e

    # Write the credentials file in the exact shape the CLI used to
    # produce — ``expiresAt`` MILLISECONDS (CLI compares to ``Date.now()``
    # internally so seconds-since-epoch would round to year-1970 and
    # trigger spurious refresh paths), plus ``clientId`` (fixed public id)
    # so the CLI doesn't have to re-discover it on first use.
    now_ms = int(time.time() * 1000)
    payload = {
        "claudeAiOauth": {
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "expiresAt": now_ms + expires_in * 1000 if expires_in else None,
            "scopes": scopes,
            "clientId": _OAUTH_CLIENT_ID,
        }
    }
    try:
        _write_credentials(payload)
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"자격증명 파일을 쓰지 못했습니다: {e}",
        ) from e

    async with _sessions_lock:
        _sessions.pop(session_id, None)

    try:
        cred = await _ensure_active_credential(db)
        cred_msg = f"활성 모델: {cred.model}"
    except Exception as e:
        log.warning("claude_auth.activate_failed", error=str(e))
        cred_msg = "단, AI 키 활성화에 실패했습니다 — 설정에서 수동으로 활성화해 주세요."
    log.info("claude_auth.login_success")
    return ActionOut(
        ok=True,
        detail=(
            "Claude 로그인 완료. 자격증명이 저장되고 AI 키가 자동으로 활성화되었습니다. "
            f"({cred_msg})"
        ),
    )


@router.post(
    "/{session_id}/cancel",
    response_model=ActionOut,
    response_model_by_alias=True,
)
async def cancel_route(session_id: str) -> ActionOut:
    async with _sessions_lock:
        sess = _sessions.pop(session_id, None)
    if sess is None:
        return ActionOut(ok=True, detail="이미 종료된 세션입니다.")
    return ActionOut(ok=True, detail="로그인 세션을 취소했습니다.")


@router.post(
    "/credentials",
    response_model=ActionOut,
    response_model_by_alias=True,
)
async def credentials_route(
    body: CredentialsIn,
    db: AsyncSession = Depends(get_db),
) -> ActionOut:
    """Write a user-supplied ``.credentials.json`` to the backend volume.

    Escape hatch for users who already have working credentials from
    another machine — they paste the file content here verbatim.
    """
    raw = body.credentials
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=400,
                detail=f"붙여넣은 내용을 JSON 으로 파싱하지 못했습니다: {e}",
            )
    else:
        parsed = raw
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=400,
            detail="자격증명은 객체(JSON object) 여야 합니다.",
        )

    oauth = parsed.get("claudeAiOauth")
    if not isinstance(oauth, dict) or not oauth.get("accessToken"):
        raise HTTPException(
            status_code=400,
            detail=(
                "claudeAiOauth.accessToken 가 없습니다. "
                "host 의 ~/.claude/.credentials.json 전체 내용을 그대로 붙여넣어 주세요."
            ),
        )

    try:
        _write_credentials(parsed)
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"자격증명 파일을 쓰지 못했습니다: {e}",
        )

    try:
        cred = await _ensure_active_credential(db)
        cred_msg = f"활성 모델: {cred.model}"
    except Exception as e:
        log.warning("claude_auth.activate_failed", error=str(e))
        cred_msg = "단, AI 키 활성화에 실패했습니다 — 설정에서 수동으로 활성화해 주세요."
    log.info("claude_auth.manual_credentials_saved")
    return ActionOut(
        ok=True,
        detail=f"자격증명을 저장하고 AI 키를 활성화했습니다. ({cred_msg})",
    )


@router.post("/logout", response_model=ActionOut, response_model_by_alias=True)
async def logout_route() -> ActionOut:
    if not _CRED_FILE.exists():
        return ActionOut(ok=True, detail="이미 로그아웃 상태입니다.")
    try:
        _CRED_FILE.unlink()
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"자격증명 삭제 실패: {e}")
    return ActionOut(
        ok=True,
        detail="Claude 자격증명을 삭제했습니다. 다시 사용하려면 로그인하세요.",
    )
