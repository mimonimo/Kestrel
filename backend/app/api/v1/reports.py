"""사용자 신고/문의 — 관리자에게 SNS 로 즉시 알림 + 감사 기록.

운영 알림 정책상 시스템 에러 알람은 "지속·반복되는 큰 문제"에서만 울리지만,
사용자가 직접 올린 신고는 누락되면 안 되므로 접수 즉시 알림을 발행한다.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_optional_user
from app.core.audit import AuditAction, record_audit
from app.core.database import get_db
from app.core.rate_limit import enforce_report_rate_limit
from app.core.request_ip import client_ip
from app.models import User
from app.schemas.vulnerability import CamelModel
from app.services.notify import publish_alert

router = APIRouter(prefix="/reports", tags=["reports"])

_CATEGORY_LABELS = {
    "bug": "버그/오류",
    "abuse": "부적절한 콘텐츠",
    "idea": "제안/의견",
    "other": "기타",
}


class ReportIn(CamelModel):
    category: str = Field(default="bug", max_length=32)
    message: str = Field(min_length=5, max_length=2000)
    url: str | None = Field(default=None, max_length=500)
    contact: str | None = Field(default=None, max_length=200)


class ReportOut(CamelModel):
    ok: bool
    message: str


@router.post("", response_model=ReportOut, response_model_by_alias=True)
async def submit_report(
    body: ReportIn,
    request: Request,
    me: User | None = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    """신고/문의 접수 → SNS 알림(관리자 이메일) + 감사 로그. IP 기준 레이트리밋."""
    ip = client_ip(request) or "unknown"
    await enforce_report_rate_limit(ip)

    cat = _CATEGORY_LABELS.get(body.category, body.category)
    who = f"{me.email} ({me.username})" if me is not None else f"비회원 ({ip})"
    url = body.url or "-"
    contact = (body.contact or "").strip()

    subject = f"[Kestrel 신고] {cat}"
    text = (
        f"분류: {cat}\n"
        f"신고자: {who}\n"
        f"회신 연락처: {contact or '-'}\n"
        f"페이지: {url}\n"
        f"IP: {ip}\n"
        f"────────────\n"
        f"{body.message}"
    )
    await publish_alert(subject, text)

    await record_audit(
        db,
        action=AuditAction.USER_REPORT,
        actor=me,
        actor_label=None if me is not None else "비회원",
        request=request,
        target=cat,
        detail=body.message[:480],
    )
    return ReportOut(ok=True, message="신고가 접수되었습니다. 감사합니다.")
