"""Dashboard-driven Claude OAuth login (PR 10-AD).

Drives `claude setup-token` (the device-code OAuth flow shipped with the
Claude Code CLI) from inside the backend container, exposing only:

    1. Start a session — backend spawns the CLI in a PTY, captures the
       authorization URL from its stdout, returns it to the frontend.
    2. Submit the OAuth code — frontend posts the code that the user
       received from the Anthropic OAuth page; backend writes it into
       the CLI's stdin and waits for the subprocess to exit cleanly.
    3. Status / logout — read or remove ``~/.claude/.credentials.json``.

The user never touches a terminal. The CLI process is an implementation
detail; from the user's perspective it's a one-button flow in settings.

Why a PTY?
    `claude setup-token` checks ``isTTY`` on stdin/stdout/stderr — when
    those are pipes (not a TTY) it refuses to start the OAuth flow.
    `pty.openpty()` gives us a kernel pseudo-terminal pair so the child
    sees a real TTY but we still get programmatic read/write on the
    master fd.

Why a wide window size?
    The CLI line-wraps the OAuth URL at the terminal width. We
    `TIOCSWINSZ` the master fd to 1 row × 400 cols so the URL never
    splits and we can extract it with a simple regex.
"""
from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import re
import secrets
import shutil
import signal
import struct
import termios
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.logging import get_logger
from app.models import AiCredential, AppSettings

router = APIRouter(prefix="/settings/claude-auth", tags=["claude-auth"])
log = get_logger(__name__)


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
    expires_at: int | None = None  # epoch seconds
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


# ---------------------------------------------------------------------------
# Login session registry
# ---------------------------------------------------------------------------

_CLAUDE_HOME = Path("/home/app/.claude")
_CRED_FILE = _CLAUDE_HOME / ".credentials.json"
_SESSION_TTL_SECONDS = 600  # 10 min — caps a forgotten OAuth tab


@dataclass
class _LoginSession:
    sid: str
    proc: asyncio.subprocess.Process | None
    master_fd: int
    url: str
    started_at: float
    output: bytes = field(default_factory=bytes)


_sessions: dict[str, _LoginSession] = {}
_sessions_lock = asyncio.Lock()


def _gc_sessions() -> None:
    """Reap sessions older than the TTL — keeps the registry bounded."""
    now = time.time()
    stale = [
        sid for sid, s in _sessions.items() if now - s.started_at > _SESSION_TTL_SECONDS
    ]
    for sid in stale:
        s = _sessions.pop(sid, None)
        if s is None:
            continue
        try:
            if s.proc is not None and s.proc.returncode is None:
                s.proc.kill()
        except Exception:
            pass
        try:
            os.close(s.master_fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _set_window_size(fd: int, rows: int = 1, cols: int = 400) -> None:
    """Tell the kernel the TTY is wide enough that the URL won't wrap."""
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


_ANSI_ESC_RE = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]")
_OSC_RE = re.compile(rb"\x1b\][^\x07]*\x07")
_URL_RE = re.compile(rb"https://claude\.com/cai/oauth/authorize\?[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")


def _strip_ansi(buf: bytes) -> bytes:
    """Remove escape sequences so the URL regex matches cleanly."""
    return _OSC_RE.sub(b"", _ANSI_ESC_RE.sub(b"", buf))


async def _spawn_setup_token() -> tuple[asyncio.subprocess.Process, int, str]:
    """Launch `claude setup-token` in a PTY and capture the OAuth URL.

    Returns ``(proc, master_fd, url)``. The master fd is left open — caller
    keeps it for the subsequent stdin write (the OAuth code).
    """
    if shutil.which("claude") is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "이 컨테이너에 Claude Code CLI 가 없어 로그인 흐름을 시작할 수 없습니다. "
                "INSTALL_CLAUDE_CLI=1 (기본값) 로 백엔드 이미지를 다시 빌드해 주세요."
            ),
        )

    master_fd, slave_fd = pty.openpty()
    _set_window_size(master_fd)
    env = {**os.environ, "TERM": "xterm-256color", "HOME": str(_CLAUDE_HOME.parent)}
    try:
        proc = await asyncio.create_subprocess_exec(
            "claude",
            "setup-token",
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            start_new_session=True,
        )
    finally:
        os.close(slave_fd)

    # Read until the URL appears (or 25s elapse — the CLI's startup banner
    # animation usually finishes within ~3s).
    deadline = asyncio.get_event_loop().time() + 25.0
    buf = b""
    url: str | None = None
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.15)
        try:
            chunk = await asyncio.to_thread(_read_nonblocking, master_fd)
        except OSError:
            chunk = b""
        if chunk:
            buf += chunk
            stripped = _strip_ansi(buf)
            m = _URL_RE.search(stripped)
            if m:
                url = m.group(0).decode()
                break
        if proc.returncode is not None:
            # CLI exited before printing a URL — usually because it's
            # missing entirely or the OAuth client_id was rejected.
            break

    if url is None:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        os.close(master_fd)
        snippet = _strip_ansi(buf)[-400:].decode("utf-8", errors="replace").strip()
        raise HTTPException(
            status_code=502,
            detail=(
                "Claude OAuth URL을 25초 안에 받지 못했습니다. "
                f"CLI 출력 발췌: {snippet or '(없음)'}"
            ),
        )

    log.info("claude_auth.url_captured", proc_pid=proc.pid)
    return proc, master_fd, url


def _read_nonblocking(fd: int) -> bytes:
    """Drain whatever is available on the master fd without blocking."""
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    chunks: list[bytes] = []
    try:
        while True:
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        fcntl.fcntl(fd, fcntl.F_SETFL, flags)
    return b"".join(chunks)


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


def _claude_version() -> str | None:
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
    proc, master_fd, url = await _spawn_setup_token()
    sid = secrets.token_urlsafe(16)
    sess = _LoginSession(
        sid=sid,
        proc=proc,
        master_fd=master_fd,
        url=url,
        started_at=time.time(),
    )
    async with _sessions_lock:
        _sessions[sid] = sess
    return StartOut(session_id=sid, url=url)


_DEFAULT_LABEL = "Claude 구독 (대시보드 로그인)"
_DEFAULT_PROVIDER = "claude_cli"
_DEFAULT_MODEL = "claude-sonnet-4-6"


async def _ensure_active_credential(db: AsyncSession) -> AiCredential:
    """Make sure there's exactly one ``claude_cli`` credential and it's active.

    Called right after a successful dashboard login so the user doesn't
    have to also visit the model-label form to activate something —
    the analyzer can immediately route to the freshly-saved OAuth.

    Picks the first existing claude_cli row if any (preserves the user's
    chosen model), otherwise creates one with the default model. Always
    sets it as the active credential in the singleton AppSettings.
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
            # NOT NULL so a sentinel keeps the schema happy without
            # storing real secrets.
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
    if sess is None or sess.proc is None:
        raise HTTPException(
            status_code=404,
            detail="로그인 세션을 찾을 수 없습니다. 다시 시작해 주세요.",
        )
    if sess.proc.returncode is not None:
        # Subprocess already exited — clean up and report.
        await _drop_session(session_id)
        raise HTTPException(
            status_code=409,
            detail=(
                f"로그인 세션이 이미 종료되었습니다 (exit={sess.proc.returncode}). "
                "다시 시작해 주세요."
            ),
        )

    code = body.code.strip()
    try:
        # Strip newlines from the user's paste so trailing CR doesn't
        # double-submit. Append our own \n to actually submit.
        cleaned = code.replace("\r", "").replace("\n", "")
        os.write(sess.master_fd, cleaned.encode() + b"\n")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"코드 전송 실패: {e}")

    # Drain master_fd while waiting for the subprocess to exit so we have
    # full diagnostic output if it hangs (the CLI sometimes prompts again
    # after the code, e.g. asking the user to confirm a workspace, which
    # we want to surface in the timeout message). 60s cap covers slow
    # OAuth token exchange on poor networks.
    deadline = asyncio.get_event_loop().time() + 60.0
    timed_out = False
    while True:
        try:
            chunk = await asyncio.to_thread(_read_nonblocking, sess.master_fd)
            if chunk:
                sess.output += chunk
        except OSError:
            pass
        if sess.proc.returncode is not None:
            break
        try:
            await asyncio.wait_for(sess.proc.wait(), timeout=0.4)
            break
        except asyncio.TimeoutError:
            if asyncio.get_event_loop().time() > deadline:
                timed_out = True
                break

    if timed_out:
        # Capture one final drain before killing.
        try:
            chunk = await asyncio.to_thread(_read_nonblocking, sess.master_fd)
            if chunk:
                sess.output += chunk
        except OSError:
            pass
        try:
            sess.proc.kill()
        except ProcessLookupError:
            pass
        snippet = _strip_ansi(sess.output)[-800:].decode(
            "utf-8", errors="replace"
        ).strip()
        await _drop_session(session_id)
        raise HTTPException(
            status_code=504,
            detail=(
                "Claude CLI 가 60초 안에 응답하지 않았습니다. CLI 출력 발췌: "
                f"{snippet or '(없음)'}"
            ),
        )

    rc = sess.proc.returncode
    await _drop_session(session_id)

    creds = _read_credentials()
    if rc == 0 and creds is not None:
        # Auto-create + activate the AI credential row so the analyzer
        # can immediately use the new OAuth without a second click.
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

    snippet = _strip_ansi(sess.output)[-800:].decode(
        "utf-8", errors="replace"
    ).strip()
    log.warning("claude_auth.login_failed", rc=rc, snippet=snippet[:400])
    raise HTTPException(
        status_code=400,
        detail=(
            f"Claude 로그인이 완료되지 못했습니다 (exit={rc}). "
            f"CLI 출력 발췌: {snippet or '(없음)'}"
        ),
    )


@router.post(
    "/{session_id}/cancel",
    response_model=ActionOut,
    response_model_by_alias=True,
)
async def cancel_route(session_id: str) -> ActionOut:
    sess = _sessions.get(session_id)
    if sess is None:
        return ActionOut(ok=True, detail="이미 종료된 세션입니다.")
    await _drop_session(session_id)
    return ActionOut(ok=True, detail="로그인 세션을 취소했습니다.")


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


async def _drop_session(sid: str) -> None:
    async with _sessions_lock:
        sess = _sessions.pop(sid, None)
    if sess is None:
        return
    if sess.proc is not None and sess.proc.returncode is None:
        try:
            sess.proc.send_signal(signal.SIGTERM)
            await asyncio.wait_for(sess.proc.wait(), timeout=2.0)
        except (ProcessLookupError, asyncio.TimeoutError):
            try:
                sess.proc.kill()
            except ProcessLookupError:
                pass
    try:
        os.close(sess.master_fd)
    except OSError:
        pass
