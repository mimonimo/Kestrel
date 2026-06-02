"""감사 로그 기록 헬퍼 + 액션 상수 (PR 10-DX).

``record_audit`` 는 절대 요청을 깨뜨리지 않는다(자체 try/except + 자체 commit).
인증·관리 흐름 어디에서 호출해도 부수효과로 인한 실패가 없도록 best-effort.

민감정보(비밀번호·토큰·시크릿 값)는 detail 에 넣지 않는다.
"""
from __future__ import annotations

import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.request_ip import client_ip
from app.models import AuditLog, User

log = structlog.get_logger(__name__)


# ─── 액션 상수 ───────────────────────────────────────────
class AuditAction:
    LOGIN_SUCCESS = "login.success"
    LOGIN_FAILURE = "login.failure"
    SIGNUP = "signup"
    PASSWORD_CHANGE = "password.change"
    USER_ROLE_CHANGE = "user.role_change"
    USER_DELETE = "user.delete"
    ADMIN_KEYS_UPDATE = "admin.keys_update"


# 화면 표시용 한국어 라벨 (프론트와 별개로 API 에도 노출해 일관성).
ACTION_LABELS: dict[str, str] = {
    AuditAction.LOGIN_SUCCESS: "로그인 성공",
    AuditAction.LOGIN_FAILURE: "로그인 실패",
    AuditAction.SIGNUP: "회원가입",
    AuditAction.PASSWORD_CHANGE: "비밀번호 변경",
    AuditAction.USER_ROLE_CHANGE: "역할 변경",
    AuditAction.USER_DELETE: "사용자 삭제",
    AuditAction.ADMIN_KEYS_UPDATE: "외부 키 변경",
}


async def record_audit(
    db: AsyncSession,
    *,
    action: str,
    actor: User | None = None,
    actor_label: str | None = None,
    request: Request | None = None,
    target: str | None = None,
    detail: str | None = None,
) -> None:
    """감사 이벤트 1건 기록. 실패해도 호출자 흐름은 계속된다."""
    try:
        ip = client_ip(request) if request is not None else None
        ua = None
        if request is not None:
            ua = (request.headers.get("user-agent") or "")[:512] or None
        label = actor_label or (actor.email if actor is not None else None)
        row = AuditLog(
            actor_user_id=actor.id if actor is not None else None,
            actor_label=label[:255] if label else None,
            action=action,
            target=target[:255] if target else None,
            detail=detail[:512] if detail else None,
            ip=ip[:64] if ip else None,
            user_agent=ua,
        )
        db.add(row)
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — 감사 실패가 인증/관리 동작을 막지 않도록
        log.warning("audit_record_failed", action=action, error=str(exc))
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001
            pass


def _coerce_uuid(raw: str | None) -> uuid.UUID | None:
    try:
        return uuid.UUID(raw) if raw else None
    except (ValueError, TypeError):
        return None
